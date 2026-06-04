//! openraft 0.9 集成:TypeConfig + 命令 + redb log storage + state machine + HTTP network。
//!
//! NodeId 用 u64(openraft 要求 Copy,String 不行);peer 的 "meta-1" 地址塞进 BasicNode。

// 阶段②接线中;接线完成后移除本行。
#![allow(dead_code)]

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

/// 启动单节点 metadata raft(阶段①;多节点在阶段④用 add_learner + change_membership)。
pub(crate) async fn start_single_node(
    node_id: u64,
    db: Arc<redb::Database>,
    app: AppStateRef,
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
    let raft = openraft::Raft::new(
        node_id,
        config,
        network::NetworkFactory,
        log_store,
        state_machine,
    )
    .await
    .map_err(|err| format!("{err:?}"))?;
    // 单成员集初始化(幂等:已初始化返回 NotAllowed,忽略)。
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

    /// 启动单节点元数据 raft 并接管写路径(集群模式)。async 上下文(server 启动)调用一次,幂等。
    /// 顺序:建 raft(state machine 持 holder)→ 回填 Weak → 安装句柄。
    pub async fn init_metadata_raft(self: &Arc<Self>, node_id: u64) -> Result<(), String> {
        if self.meta_raft.get().is_some() {
            return Ok(());
        }
        let db_path = self.data_dir.join(".rustio_meta_raft.redb");
        let db = Arc::new(
            redb::Database::create(&db_path).map_err(|err| format!("打开 raft redb 失败: {err}"))?,
        );
        let raft = start_single_node(node_id, db, self.meta_raft_app.clone()).await?;
        let _ = self.meta_raft_app.set(Arc::downgrade(self));
        let _ = self.meta_raft.set(raft);
        Ok(())
    }
}

