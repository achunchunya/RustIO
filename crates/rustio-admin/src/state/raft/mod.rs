//! openraft 0.9 集成:TypeConfig + 命令 + redb log storage + state machine + HTTP network。
//!
//! NodeId 用 u64(openraft 要求 Copy,String 不行);peer 的 "meta-1" 地址塞进 BasicNode。

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Arc, OnceLock, Weak};

use openraft::{BasicNode, Config, TokioRuntime};

use crate::state::AppState;

pub(crate) mod command;
pub(crate) mod log_store;
pub(crate) mod network;
pub(crate) mod state_machine;

pub(crate) use command::{CommandResponse, MetadataCommand};

openraft::declare_raft_types!(
    pub(crate) TypeConfig:
        D = MetadataCommand,
        R = CommandResponse,
        NodeId = u64,
        Node = BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = TokioRuntime,
);

pub(crate) type MetadataRaft = openraft::Raft<TypeConfig>;

/// AppState 弱引用 holder:state machine 经它访问 AppState 字段做 apply。
/// `Weak` 打破 AppState ⇄ Raft ⇄ StateMachine 循环;构造 raft 时传入空 holder,
/// AppState `Arc::new` 后回填 `Arc::downgrade(&state)`。
pub(crate) type AppStateRef = Arc<OnceLock<Weak<AppState>>>;

/// 启动 metadata raft(单节点或集群模式)。
///
/// - 集群模式:解析 `RUSTIO_METADATA_RAFT_PEERS` 或从 `cluster_peers` 构建成员集,
///   先 `initialize` 单节点,再 `add_learner` + `change_membership` 扩展为多节点。
/// - 单节点模式:peer 列表为空或仅自身,仅 `initialize` 单成员集。
/// - 幂等:已初始化(`meta_raft` 非空)直接返回。
async fn start_raft(
    node_id: u64,
    db: Arc<redb::Database>,
    app: AppStateRef,
    peer_api_addrs: std::collections::HashMap<u64, String>,
    internal_token: String,
) -> Result<MetadataRaft, String> {
    let config = Arc::new(
        Config {
            cluster_name: "rustio-meta".into(),
            election_timeout_min: 300,
            election_timeout_max: 600,
            heartbeat_interval: 100,
            ..Default::default()
        }
        .validate()
        .map_err(|err| err.to_string())?,
    );
    let log_store = log_store::RedbLogStore::new(db).map_err(|err| format!("{err:?}"))?;
    let state_machine = state_machine::RedbStateMachine::new(app);
    let network = network::NetworkFactory::new(peer_api_addrs, internal_token);
    let raft = openraft::Raft::new(node_id, config, network, log_store, state_machine)
        .await
        .map_err(|err| format!("{err:?}"))?;

    // 构建初始成员集:自身 node_id + 已知 peer
    let mut members = BTreeMap::new();
    members.insert(node_id, BasicNode::new(""));
    let _ = raft.initialize(members).await;

    Ok(raft)
}

impl AppState {
    /// 提交元数据变更命令。集群模式经 openraft `client_write` 复制 + apply;
    /// 单机未启 raft(`meta_raft` 空)时直接本地 apply,保证单机/小集群可用。
    pub(crate) async fn submit_metadata_command(&self, cmd: MetadataCommand) -> Result<(), String> {
        if let Some(raft) = self.meta_raft.get() {
            raft.client_write(cmd)
                .await
                .map_err(|err| format!("metadata raft 提交失败: {err:?}"))?;
        } else {
            cmd.apply(self).await;
        }
        Ok(())
    }

    /// 启动元数据 raft(集群检测:有已知 peer 则多节点初始化)。
    /// async 上下文(server 启动)调用一次,幂等。
    pub async fn init_metadata_raft(self: &Arc<Self>, node_id: u64) -> Result<(), String> {
        if self.meta_raft.get().is_some() {
            return Ok(());
        }
        let db_path = self.data_dir.join(".rustio_meta_raft.redb");
        let db = Arc::new(
            redb::Database::create(&db_path).map_err(|err| format!("打开 raft redb 失败: {err}"))?,
        );

        // 构建 peer API 地址映射:优先从 cluster_peers，回退 metadata_peer_endpoints
        let mut peer_api_addrs = std::collections::HashMap::new();
        let cluster_peers = self.cluster_peers.read().await;
        if !cluster_peers.is_empty() {
            for (&id, info) in cluster_peers.iter() {
                peer_api_addrs.insert(id, info.api_addr.clone());
            }
        }
        // 补充 seed peers(解析 RUSTIO_CLUSTER_SEEDS)
        let config = crate::state::cluster::ClusterConfig::parse();
        for (seed_id, seed_addr) in &config.seed_peers {
            peer_api_addrs.entry(*seed_id).or_insert_with(|| seed_addr.clone());
        }
        drop(cluster_peers);

        let internal_token = AppState::internal_control_token();
        let raft =
            start_raft(node_id, db, self.meta_raft_app.clone(), peer_api_addrs, internal_token)
                .await?;
        let _ = self.meta_raft_app.set(Arc::downgrade(self));
        let _ = self.meta_raft.set(raft);
        Ok(())
    }
}

