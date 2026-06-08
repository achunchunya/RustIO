//! openraft `RaftStateMachine`:apply 命令到 AppState 控制面字段 + snapshot 含业务态。
//!
//! 状态机持久化两类:① openraft 元数据(last_applied/last_membership)落 redb 表 `raft_sm_meta`;
//! ② 业务状态真相源是 AppState 的 RwLock 字段,apply 经 `Weak<AppState>` 回填,
//! snapshot 经 `build_metadata_snapshot`/`apply_remote_metadata_raft_sync` 序列化/恢复。
//! `Weak` 打破 AppState ⇄ Raft ⇄ StateMachine 的循环引用。

use std::io::Cursor;
use std::sync::Arc;

use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{
    AnyError, BasicNode, Entry, EntryPayload, LogId, OptionalSend, Snapshot, SnapshotMeta,
    StorageError, StorageIOError, StoredMembership,
};
use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::state::AppState;

use super::{AppStateRef, CommandResponse, TypeConfig};

const SM_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_sm_meta");
const KEY_SM_DATA: &str = "sm_data";

/// openraft 必须持久化的状态机元数据(落 redb 表 `raft_sm_meta`)。
#[derive(Clone, Default, Serialize, Deserialize)]
struct StateMachineData {
    last_applied: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, BasicNode>,
}

#[derive(Clone)]
pub(crate) struct RedbStateMachine {
    data: Arc<Mutex<StateMachineData>>,
    db: Arc<Database>,
    /// 指向 AppState 的弱引用 holder(打破循环);AppState 构造后由 bootstrap 回填。
    app: AppStateRef,
}

fn io_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<u64> {
    StorageIOError::read_state_machine(AnyError::new(&e)).into()
}

impl RedbStateMachine {
    pub(crate) fn new(app: AppStateRef, db: Arc<Database>) -> Result<Self, StorageError<u64>> {
        // 确保表存在并从 redb 恢复已持久化的 last_applied/last_membership。
        let data = {
            let txn = db.begin_write().map_err(io_err)?;
            {
                txn.open_table(SM_META_TABLE).map_err(io_err)?;
            }
            txn.commit().map_err(io_err)?;
            let txn = db.begin_read().map_err(io_err)?;
            let table = txn.open_table(SM_META_TABLE).map_err(io_err)?;
            match table.get(KEY_SM_DATA).map_err(io_err)? {
                Some(bytes) => serde_json::from_slice(bytes.value()).map_err(io_err)?,
                None => StateMachineData::default(),
            }
        };
        Ok(Self {
            data: Arc::new(Mutex::new(data)),
            db,
            app,
        })
    }

    /// 取就绪的 AppState 强引用;未回填(初始化早期)或已 drop(关闭中)时返回 None,业务 apply 跳过。
    fn app_state(&self) -> Option<Arc<AppState>> {
        self.app.get().and_then(std::sync::Weak::upgrade)
    }

    /// 把内存中的 SM 元数据持久化到 redb(在业务 apply 成功之后调用)。
    fn persist_data(&self, data: &StateMachineData) -> Result<(), StorageError<u64>> {
        let bytes = serde_json::to_vec(data).map_err(io_err)?;
        let txn = self.db.begin_write().map_err(io_err)?;
        {
            let mut table = txn.open_table(SM_META_TABLE).map_err(io_err)?;
            table.insert(KEY_SM_DATA, bytes.as_slice()).map_err(io_err)?;
        }
        txn.commit().map_err(io_err)?;
        Ok(())
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
                    // AppState 就绪时把命令应用到控制面字段(含数据面物化);未就绪(早期)仅记 last_applied。
                    if let Some(app) = &app {
                        cmd.apply(app).await;
                    } else {
                        tracing::warn!("raft apply: AppState 未就绪(Weak 未回填),命令跳过仅记 last_applied");
                    }
                    responses.push(CommandResponse { ok: true });
                }
                EntryPayload::Membership(membership) => {
                    last_membership = Some((entry.log_id, membership));
                    responses.push(CommandResponse { ok: true });
                }
            }
        }
        // 先完成业务 apply,再持久化 last_applied/last_membership 到 redb。
        // 顺序保证 at-least-once:崩溃在持久化前 → last_applied 未推进 → 重启重放(apply 幂等)。
        let mut data = self.data.lock().await;
        if let Some(log_id) = last_applied {
            data.last_applied = Some(log_id);
        }
        if let Some((log_id, membership)) = last_membership {
            data.last_membership = StoredMembership::new(Some(log_id), membership);
        }
        self.persist_data(&data)?;
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
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        // 反序列化快照业务态并回写 AppState(follower 经快照追赶),再同步 openraft 元数据落 redb。
        let bytes = snapshot.into_inner();
        if !bytes.is_empty() {
            if let Ok(business) =
                serde_json::from_slice::<crate::state::MetadataRaftSnapshot>(&bytes)
            {
                if let Some(app) = self.app_state() {
                    app.install_metadata_business_snapshot(business).await;
                }
            } else {
                tracing::warn!("install_snapshot:业务态快照反序列化失败,仅同步 raft 元数据");
            }
        }
        let mut data = self.data.lock().await;
        data.last_applied = meta.last_log_id;
        data.last_membership = meta.last_membership.clone();
        self.persist_data(&data)?;
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
        let (last_log_id, last_membership) = {
            let data = self.data.lock().await;
            (data.last_applied, data.last_membership.clone())
        };
        // 快照体 = 业务态全字段(复用集群备份的 build_metadata_snapshot);无 AppState 时为空。
        let bytes = match self.app_state() {
            Some(app) => {
                let business = app.build_metadata_snapshot().await;
                serde_json::to_vec(&business).map_err(io_err)?
            }
            None => Vec::new(),
        };
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
