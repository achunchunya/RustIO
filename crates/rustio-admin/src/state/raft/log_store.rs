//! 基于 redb 的 openraft `RaftLogStorage`:持久化 log entries + vote + committed/last_purged。
//!
//! 表:`raft_log`(u64 index → 序列化 Entry)、`raft_meta`(固定 key → vote/committed/last_purged)。
//! 序列化用 serde_json(openraft 开 serde feature 后 Entry/Vote/LogId 均可序列化)。

use std::fmt::Debug;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{LogFlushed, RaftLogReader, RaftLogStorage};
use openraft::{AnyError, Entry, LogId, LogState, OptionalSend, StorageError, StorageIOError, Vote};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use super::TypeConfig;

const LOG_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_meta");
const KEY_VOTE: &str = "vote";
const KEY_COMMITTED: &str = "committed";
const KEY_LAST_PURGED: &str = "last_purged";

#[derive(Clone)]
pub(crate) struct RedbLogStore {
    db: Arc<Database>,
}

fn io_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<u64> {
    StorageIOError::read_logs(AnyError::new(&e)).into()
}

impl RedbLogStore {
    pub(crate) fn new(db: Arc<Database>) -> Result<Self, StorageError<u64>> {
        let txn = db.begin_write().map_err(io_err)?;
        {
            txn.open_table(LOG_TABLE).map_err(io_err)?;
            txn.open_table(META_TABLE).map_err(io_err)?;
        }
        txn.commit().map_err(io_err)?;
        Ok(Self { db })
    }

    fn read_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(io_err)?;
        let table = txn.open_table(META_TABLE).map_err(io_err)?;
        Ok(table.get(key).map_err(io_err)?.map(|v| v.value().to_vec()))
    }

    fn write_meta(&self, key: &str, bytes: &[u8]) -> Result<(), StorageError<u64>> {
        let txn = self.db.begin_write().map_err(io_err)?;
        {
            let mut table = txn.open_table(META_TABLE).map_err(io_err)?;
            table.insert(key, bytes).map_err(io_err)?;
        }
        txn.commit().map_err(io_err)?;
        Ok(())
    }
}

impl RaftLogReader<TypeConfig> for RedbLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(io_err)?;
        let table = txn.open_table(LOG_TABLE).map_err(io_err)?;
        let mut out = Vec::new();
        for item in table.range(range).map_err(io_err)? {
            let (_, value) = item.map_err(io_err)?;
            let entry: Entry<TypeConfig> = serde_json::from_slice(value.value()).map_err(io_err)?;
            out.push(entry);
        }
        Ok(out)
    }
}

impl RaftLogStorage<TypeConfig> for RedbLogStore {
    type LogReader = Self;

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        let last_purged: Option<LogId<u64>> = self
            .read_meta(KEY_LAST_PURGED)?
            .and_then(|b| serde_json::from_slice(&b).ok());

        let txn = self.db.begin_read().map_err(io_err)?;
        let table = txn.open_table(LOG_TABLE).map_err(io_err)?;
        let last_log_id = match table.last().map_err(io_err)? {
            Some((_, value)) => {
                let entry: Entry<TypeConfig> =
                    serde_json::from_slice(value.value()).map_err(io_err)?;
                Some(entry.log_id)
            }
            None => last_purged,
        };

        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id,
        })
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let bytes = serde_json::to_vec(vote).map_err(io_err)?;
        self.write_meta(KEY_VOTE, &bytes)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        Ok(self
            .read_meta(KEY_VOTE)?
            .and_then(|b| serde_json::from_slice(&b).ok()))
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<u64>>,
    ) -> Result<(), StorageError<u64>> {
        let bytes = serde_json::to_vec(&committed).map_err(io_err)?;
        self.write_meta(KEY_COMMITTED, &bytes)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        Ok(self
            .read_meta(KEY_COMMITTED)?
            .and_then(|b| serde_json::from_slice(&b).ok()))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        {
            let txn = self.db.begin_write().map_err(io_err)?;
            {
                let mut table = txn.open_table(LOG_TABLE).map_err(io_err)?;
                for entry in entries {
                    let bytes = serde_json::to_vec(&entry).map_err(io_err)?;
                    table
                        .insert(entry.log_id.index, bytes.as_slice())
                        .map_err(io_err)?;
                }
            }
            txn.commit().map_err(io_err)?;
        }
        // redb 写事务已 commit(持久化完成),通知 openraft。
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        // 删除 index >= log_id.index 的 entry(冲突回滚)。
        let txn = self.db.begin_write().map_err(io_err)?;
        {
            let mut table = txn.open_table(LOG_TABLE).map_err(io_err)?;
            let keys: Vec<u64> = table
                .range(log_id.index..)
                .map_err(io_err)?
                .filter_map(|item| item.ok().map(|(k, _)| k.value()))
                .collect();
            for key in keys {
                table.remove(key).map_err(io_err)?;
            }
        }
        txn.commit().map_err(io_err)?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        // 删除 index <= log_id.index 的 entry,并记录 last_purged。
        {
            let txn = self.db.begin_write().map_err(io_err)?;
            {
                let mut table = txn.open_table(LOG_TABLE).map_err(io_err)?;
                let keys: Vec<u64> = table
                    .range(..=log_id.index)
                    .map_err(io_err)?
                    .filter_map(|item| item.ok().map(|(k, _)| k.value()))
                    .collect();
                for key in keys {
                    table.remove(key).map_err(io_err)?;
                }
            }
            txn.commit().map_err(io_err)?;
        }
        let bytes = serde_json::to_vec(&log_id).map_err(io_err)?;
        self.write_meta(KEY_LAST_PURGED, &bytes)
    }
}
