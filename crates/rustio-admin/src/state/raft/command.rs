//! Raft 复制的元数据命令(细粒度增量)。
//!
//! 每种控制面元数据变更 = 一个 variant;leader 经 `raft.client_write` 提交,各节点 apply
//! 到本地 AppState 的 RwLock 字段。数据面操作(文件目录、redb、校验)留在 handler,不进 Raft log。

use std::collections::HashMap;

use rustio_core::{BucketSpec, ClusterConfigSnapshot, RemoteTierConfig, SecurityConfig};
use serde::{Deserialize, Serialize};

use crate::routes::{
    default_bucket_acl_config, default_bucket_public_access_block_config, default_legal_hold_config,
    default_object_lock_config, default_retention_config, IamRuntimeSnapshot,
};
use crate::state::AppState;

/// 元数据状态机命令。阶段②补全其余 ~20 种变更(对应现 `sync_metadata_raft` 各 reason)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum MetadataCommand {
    /// 创建 bucket。apply:insert `buckets` + 各 bucket 配置默认值
    /// (object_lock / retention / legal_hold / notification / lifecycle / acl / public_access_block)。
    CreateBucket(Box<BucketSpec>),
    /// 删除 bucket。apply:remove `buckets` 及所有 bucket 配置;retain replications/backlog。
    DeleteBucket { name: String },
    /// 设置远端分层配置全集(update/health-check/rotate/delete 统一)。apply:整体替换 + 落盘。
    #[allow(clippy::box_collection)]
    SetRemoteTiers(Box<HashMap<String, RemoteTierConfig>>),
    /// 设置安全配置 + 集群配置历史(cluster-config-apply/rollback/security-update 统一)。
    /// apply:整体替换 security + cluster_config_history + 落盘两者。
    SetSecurityAndHistory {
        security: Box<SecurityConfig>,
        history: Vec<ClusterConfigSnapshot>,
    },
    /// 设置 IAM 运行时全集(credentials/users/groups/policies/service_accounts/
    /// admin_sessions/sts_sessions)。18 种 IAM 变更经 commit_iam_runtime_change 统一提交。
    /// apply:整体替换 7 字段 + 落盘 admin_sessions。
    SetIamRuntime(Box<IamRuntimeSnapshot>),
    /// 插入/更新单个集群节点拓扑(动态成员变更加节点时复制到各节点)。
    /// apply:insert 到 `cluster_peers`,使全集群拓扑一致、EC 放置纳入新节点。
    UpsertClusterPeer(Box<crate::state::cluster::ClusterPeerInfo>),
    /// 移除单个集群节点拓扑(动态成员变更移除节点时复制到各节点)。
    /// apply:remove `cluster_peers`,使 EC 放置/布局自动收缩到剩余节点。
    RemoveClusterPeer { node_id: u64 },
}

/// 命令 apply 结果(经 openraft `client_write` 返回给调用方)。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct CommandResponse {
    pub ok: bool,
}

impl MetadataCommand {
    /// 把命令增量应用到 AppState 控制面字段。leader 与 follower 共用,保证各节点状态一致。
    /// 只改被 Raft 保护的内存字段(及必要落盘副作用);数据面(文件/redb/audit/校验)由 handler 负责。
    /// 对照现 `create_bucket_spec`/`delete_bucket_spec`(routes/buckets.rs)的内存改动序列。
    pub(crate) async fn apply(&self, app: &AppState) {
        match self {
            MetadataCommand::CreateBucket(spec) => {
                let spec = spec.as_ref().clone();
                let name = spec.name.clone();
                let lock_cfg = default_object_lock_config(&spec);
                // 数据面物化:确保 bucket 目录存在(幂等)。leader 的 handler 已建则 no-op;
                // follower apply 复制命令时必需,否则 bucket 仅存在于内存、重启丢失(靠扫目录恢复)。
                let bucket_dir = app.data_dir.join(&name);
                if let Err(err) = tokio::fs::create_dir_all(&bucket_dir).await {
                    tracing::error!(bucket = %name, "apply CreateBucket 创建目录失败: {err}");
                }
                app.buckets.write().await.insert(name.clone(), spec);
                app.bucket_object_locks
                    .write()
                    .await
                    .insert(name.clone(), lock_cfg);
                app.bucket_retentions
                    .write()
                    .await
                    .insert(name.clone(), default_retention_config());
                app.bucket_legal_holds
                    .write()
                    .await
                    .insert(name.clone(), default_legal_hold_config());
                app.bucket_notifications
                    .write()
                    .await
                    .insert(name.clone(), Vec::new());
                app.bucket_lifecycle_rules
                    .write()
                    .await
                    .insert(name.clone(), Vec::new());
                app.bucket_acls
                    .write()
                    .await
                    .insert(name.clone(), default_bucket_acl_config());
                app.bucket_public_access_blocks
                    .write()
                    .await
                    .insert(name, default_bucket_public_access_block_config());
            }
            MetadataCommand::DeleteBucket { name } => {
                // 数据面物化:移除 bucket 目录(幂等)。leader handler 已删则 no-op;follower 必需。
                let bucket_dir = app.data_dir.join(name);
                if let Err(err) = tokio::fs::remove_dir_all(&bucket_dir).await {
                    if err.kind() != std::io::ErrorKind::NotFound {
                        tracing::error!(bucket = %name, "apply DeleteBucket 移除目录失败: {err}");
                    }
                }
                app.buckets.write().await.remove(name);
                app.bucket_object_locks.write().await.remove(name);
                app.bucket_retentions.write().await.remove(name);
                app.bucket_legal_holds.write().await.remove(name);
                app.bucket_notifications.write().await.remove(name);
                app.bucket_lifecycle_rules.write().await.remove(name);
                app.bucket_acls.write().await.remove(name);
                app.bucket_public_access_blocks.write().await.remove(name);
                app.bucket_policies.write().await.remove(name);
                app.bucket_cors_rules.write().await.remove(name);
                app.bucket_tags.write().await.remove(name);
                app.bucket_encryptions.write().await.remove(name);
                app.replications
                    .write()
                    .await
                    .retain(|rule| rule.source_bucket != *name);
                app.replication_backlog
                    .write()
                    .await
                    .retain(|item| item.source_bucket != *name);
            }
            MetadataCommand::SetRemoteTiers(tiers) => {
                *app.remote_tiers.write().await = tiers.as_ref().clone();
                if let Err(err) =
                    AppState::persist_remote_tiers_snapshot(&app.data_dir, tiers.as_ref())
                {
                    tracing::warn!("持久化远端层配置失败: {err}");
                }
            }
            MetadataCommand::SetSecurityAndHistory { security, history } => {
                *app.security.write().await = security.as_ref().clone();
                *app.cluster_config_history.write().await = history.clone();
                if let Err(err) =
                    AppState::persist_security_config_snapshot(&app.data_dir, security.as_ref())
                {
                    tracing::warn!("持久化安全配置失败: {err}");
                }
                if let Err(err) =
                    AppState::persist_cluster_config_history_snapshot(&app.data_dir, history)
                {
                    tracing::warn!("持久化集群配置历史失败: {err}");
                }
            }
            MetadataCommand::SetIamRuntime(snapshot) => {
                let s = snapshot.as_ref();
                *app.credentials.write().await = s.credentials.clone();
                *app.users.write().await = s.users.clone();
                *app.groups.write().await = s.groups.clone();
                *app.policies.write().await = s.policies.clone();
                *app.service_accounts.write().await = s.service_accounts.clone();
                *app.admin_sessions.write().await = s.admin_sessions.clone();
                *app.sts_sessions.write().await = s.sts_sessions.clone();
                if let Err(err) =
                    AppState::persist_console_sessions_snapshot(&app.data_dir, &s.admin_sessions)
                {
                    tracing::warn!("持久化控制台会话失败: {err}");
                }
            }
            MetadataCommand::UpsertClusterPeer(peer) => {
                let peer = peer.as_ref().clone();
                app.cluster_peers.write().await.insert(peer.node_id, peer);
            }
            MetadataCommand::RemoveClusterPeer { node_id } => {
                app.cluster_peers.write().await.remove(node_id);
            }
        }
    }
}
