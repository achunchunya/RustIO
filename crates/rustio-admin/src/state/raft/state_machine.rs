//! openraft `RaftStateMachine`:apply 命令到 AppState 控制面字段 + 即时 snapshot。
//!
//! 状态机自身只持久化 openraft 元数据(last_applied/last_membership,阶段②-α 暂存内存,
//! 阶段②-β 落 redb);业务状态的真相源是 AppState 的 RwLock 字段,apply 经 `Weak<AppState>`
//! 回填。`Weak` 打破 AppState ⇄ Raft ⇄ StateMachine 的循环引用。

use std::io::Cursor;
use std::sync::Arc;

use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{
    AnyError, BasicNode, Entry, EntryPayload, LogId, OptionalSend, Snapshot, SnapshotMeta,
    StorageError, StorageIOError, StoredMembership,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::state::AppState;

use super::{AppStateRef, CommandResponse, TypeConfig};

/// openraft 必须持久化的状态机元数据(阶段②-α 暂存内存;阶段②-β 落 redb)。
#[derive(Clone, Default, Serialize, Deserialize)]
struct StateMachineData {
    last_applied: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, BasicNode>,
}

#[derive(Clone)]
pub(crate) struct RedbStateMachine {
    data: Arc<Mutex<StateMachineData>>,
    /// 指向 AppState 的弱引用 holder(打破循环);AppState 构造后由 bootstrap 回填。
    app: AppStateRef,
}

fn io_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<u64> {
    StorageIOError::read_state_machine(AnyError::new(&e)).into()
}

impl RedbStateMachine {
    pub(crate) fn new(app: AppStateRef) -> Self {
        Self {
            data: Arc::new(Mutex::new(StateMachineData::default())),
            app,
        }
    }

    /// 取就绪的 AppState 强引用;未回填(初始化早期)或已 drop(关闭中)时返回 None,业务 apply 跳过。
    fn app_state(&self) -> Option<Arc<AppState>> {
        self.app.get().and_then(std::sync::Weak::upgrade)
    }
}

impl RaftStateMachine<TypeConfig> for RedbStateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let data = self.data.lock().await;
        Ok((data.last_applied, data.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<CommandResponse>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let app = self.app_state();
        let mut responses = Vec::new();
        let mut last_applied = None;
        let mut last_membership = None;
        for entry in entries {
            last_applied = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(CommandResponse { ok: true }),
                EntryPayload::Normal(cmd) => {
                    // AppState 就绪时把命令应用到控制面字段;未就绪(早期)仅记 last_applied。
                    if let Some(app) = &app {
                        cmd.apply(app).await;
                    }
                    responses.push(CommandResponse { ok: true });
                }
                EntryPayload::Membership(membership) => {
                    last_membership = Some((entry.log_id, membership));
                    responses.push(CommandResponse { ok: true });
                }
            }
        }
        // 短临界区:apply 业务字段不持 data 锁,末尾统一更新 openraft 元数据。
        let mut data = self.data.lock().await;
        if let Some(log_id) = last_applied {
            data.last_applied = Some(log_id);
        }
        if let Some((log_id, membership)) = last_membership {
            data.last_membership = StoredMembership::new(Some(log_id), membership);
        }
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        _snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        // 阶段②-α:business 状态尚未入 snapshot(单节点不触发安装);仅同步 openraft 元数据。
        // 阶段③ follower 追赶时,这里复用 apply_metadata_raft_snapshot 字段映射回写 AppState。
        let mut data = self.data.lock().await;
        data.last_applied = meta.last_log_id;
        data.last_membership = meta.last_membership.clone();
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        let mut builder = self.clone();
        Ok(Some(builder.build_snapshot().await?))
    }
}

impl RaftSnapshotBuilder<TypeConfig> for RedbStateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let data = self.data.lock().await;
        let bytes = serde_json::to_vec(&*data).map_err(io_err)?;
        let last_log_id = data.last_applied;
        let last_membership = data.last_membership.clone();
        let snapshot_id = match last_log_id {
            Some(log_id) => format!("{}-{}", log_id.leader_id, log_id.index),
            None => "0-0".to_string(),
        };
        Ok(Snapshot {
            meta: SnapshotMeta {
                last_log_id,
                last_membership,
                snapshot_id,
            },
            snapshot: Box::new(Cursor::new(bytes)),
        })
    }
}
