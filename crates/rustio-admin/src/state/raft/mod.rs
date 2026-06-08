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
    members: BTreeMap<u64, BasicNode>,
    should_initialize: bool,
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
    let log_store = log_store::RedbLogStore::new(db.clone()).map_err(|err| format!("{err:?}"))?;
    let state_machine = state_machine::RedbStateMachine::new(app, db).map_err(|err| format!("{err:?}"))?;
    let network = network::NetworkFactory::new(peer_api_addrs, internal_token);
    let raft = openraft::Raft::new(node_id, config, network, log_store, state_machine)
        .await
        .map_err(|err| format!("{err:?}"))?;

    // 仅 bootstrap 节点(集群最小 node_id;单机即自身)执行 initialize,写入初始成员集;
    // 其余节点不 initialize,启动引擎后等待 leader 经 append_entries 复制 membership。
    // 这避免「每节点各自 initialize 单 voter」造成的多 leader 脑裂。
    if should_initialize {
        if let Err(err) = raft.initialize(members).await {
            // 重启后已初始化返回 NotAllowed,属正常幂等;其余情况记日志但不阻断启动。
            tracing::warn!(node_id, "metadata raft initialize: {err:?}");
        }
    }

    Ok(raft)
}

impl AppState {
    /// 提交元数据变更命令。集群模式经 openraft `client_write` 复制 + apply;
    /// 单机未启 raft(`meta_raft` 空)时直接本地 apply,保证单机/小集群可用。
    /// follower 收到写时 openraft 返回 ForwardToLeader,转发到 leader 内部写端点。
    pub(crate) async fn submit_metadata_command(&self, cmd: MetadataCommand) -> Result<(), String> {
        let Some(raft) = self.meta_raft.get() else {
            cmd.apply(self).await;
            return Ok(());
        };
        match raft.client_write(cmd.clone()).await {
            Ok(_) => Ok(()),
            Err(err) => {
                // 非 leader:openraft 返回 ForwardToLeader,取 leader 地址转发其内部写端点。
                if let Some(forward) = err.forward_to_leader() {
                    let leader_addr = forward
                        .leader_node
                        .as_ref()
                        .map(|node| node.addr.clone())
                        .filter(|addr| !addr.is_empty());
                    if let Some(addr) = leader_addr {
                        return self.forward_metadata_command_to_leader(&addr, &cmd).await;
                    }
                    return Err(format!(
                        "metadata raft 写需转发 leader,但 leader 地址未知: {err:?}"
                    ));
                }
                Err(format!("metadata raft 提交失败: {err:?}"))
            }
        }
    }

    /// 把命令 RPC 转发到 leader 的内部写端点(含一次重试)。
    async fn forward_metadata_command_to_leader(
        &self,
        leader_addr: &str,
        cmd: &MetadataCommand,
    ) -> Result<(), String> {
        let url = format!("{leader_addr}/api/v1/internal/metadata-raft/write");
        let token = AppState::internal_control_token();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|err| format!("构建转发 client 失败: {err}"))?;
        let mut last_err = String::new();
        for attempt in 0..2 {
            match client
                .post(&url)
                .header("x-rustio-internal-token", &token)
                .json(cmd)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    last_err = format!("leader 转发返回 HTTP {}", resp.status());
                }
                Err(err) => {
                    last_err = format!("leader 转发请求失败: {err}");
                }
            }
            if attempt == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
        Err(format!("metadata raft 写转发 leader 失败: {last_err}"))
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

        // 构建初始成员集与 bootstrap 决策。
        // 集群模式:初始 voter = {自身} ∪ 全部已知 peer;仅最小 node_id 节点执行 initialize,
        // 其余等待被 leader 纳入(membership 经 log 复制)。单机模式:单 voter = node_id。
        let is_cluster = self.local_node_id > 0;
        let mut members: BTreeMap<u64, BasicNode> = BTreeMap::new();
        if is_cluster {
            for (&id, addr) in &peer_api_addrs {
                members.insert(id, BasicNode::new(addr.clone()));
            }
            members
                .entry(self.local_node_id)
                .or_insert_with(|| BasicNode::new(config.local_api_addr.clone()));
        } else {
            members.insert(node_id, BasicNode::new(String::new()));
        }
        let min_voter = members.keys().next().copied().unwrap_or(node_id);
        let should_initialize = !is_cluster || node_id == min_voter;

        let internal_token = AppState::internal_control_token();
        let raft = start_raft(
            node_id,
            db,
            self.meta_raft_app.clone(),
            peer_api_addrs,
            internal_token,
            members,
            should_initialize,
        )
        .await?;
        let _ = self.meta_raft_app.set(Arc::downgrade(self));
        let _ = self.meta_raft.set(raft);
        Ok(())
    }
}

