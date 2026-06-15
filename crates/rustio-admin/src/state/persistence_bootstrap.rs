//! 磁盘持久化加载/保存与 bootstrap 初始化

use super::*;

impl AppState {
    pub(crate) fn cluster_config_history_path(data_dir: &Path) -> PathBuf {
        data_dir
            .join(".rustio_meta")
            .join("cluster-config-history.json")
    }

    pub(crate) fn load_cluster_config_history(
        data_dir: &Path,
        security: &SecurityConfig,
    ) -> Vec<ClusterConfigSnapshot> {
        let path = Self::cluster_config_history_path(data_dir);
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(history) = serde_json::from_slice::<Vec<ClusterConfigSnapshot>>(&bytes) {
                if !history.is_empty() {
                    return history;
                }
            }
        }

        vec![ClusterConfigSnapshot {
            version: "cfg-bootstrap".to_string(),
            updated_at: Utc::now(),
            updated_by: "bootstrap".to_string(),
            source: "bootstrap".to_string(),
            reason: Some("initial cluster configuration".to_string()),
            etag: format!("cfg-{}", Uuid::new_v4().simple()),
            payload: default_cluster_config_payload(security),
        }]
    }

    pub(crate) fn persist_cluster_config_history_snapshot(
        data_dir: &Path,
        history: &[ClusterConfigSnapshot],
    ) -> Result<(), String> {
        let path = Self::cluster_config_history_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(history).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }

    pub(crate) fn security_config_path(data_dir: &Path) -> PathBuf {
        data_dir.join(".rustio_meta").join("security-config.json")
    }

    pub(crate) fn load_security_config(data_dir: &Path) -> SecurityConfig {
        let defaults = default_security_config_from_env();
        let path = Self::security_config_path(data_dir);
        let persisted = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SecurityConfig>(&bytes).ok());
        persisted
            .map(|value| merge_security_config(defaults.clone(), value))
            .unwrap_or(defaults)
    }

    pub(crate) fn persist_security_config_snapshot(
        data_dir: &Path,
        config: &SecurityConfig,
    ) -> Result<(), String> {
        let path = Self::security_config_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(config).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }

    pub(crate) fn console_sessions_path(data_dir: &Path) -> PathBuf {
        data_dir.join(".rustio_meta").join("console-sessions.json")
    }

    pub(crate) fn load_console_sessions(data_dir: &Path) -> Vec<ConsoleSession> {
        let path = Self::console_sessions_path(data_dir);
        std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<ConsoleSession>>(&bytes).ok())
            .unwrap_or_default()
    }

    pub(crate) fn remote_tiers_path(data_dir: &Path) -> PathBuf {
        data_dir.join(".rustio_system").join("remote-tiers.json")
    }

    pub(crate) fn load_remote_tiers(data_dir: &Path) -> HashMap<String, RemoteTierConfig> {
        let path = Self::remote_tiers_path(data_dir);
        std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<RemoteTierConfig>>(&bytes).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|tier| (tier.name.clone(), tier))
            .collect()
    }

    pub(crate) fn persist_remote_tiers_snapshot(
        data_dir: &Path,
        tiers: &HashMap<String, RemoteTierConfig>,
    ) -> Result<(), String> {
        let path = Self::remote_tiers_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let mut payload = tiers.values().cloned().collect::<Vec<_>>();
        payload.sort_by(|left, right| left.name.cmp(&right.name));
        let bytes = serde_json::to_vec_pretty(&payload).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }

    pub(crate) fn persist_console_sessions_snapshot(
        data_dir: &Path,
        sessions: &[ConsoleSession],
    ) -> Result<(), String> {
        let path = Self::console_sessions_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(sessions).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }

    /// 打开 redb 元数据库,若文件损坏则自动删除重建(元数据可从 bucket 目录扫描恢复)。
    fn open_meta_store_or_recover(data_dir: &Path) -> MetaStore {
        let path = data_dir.join(".rustio_meta.redb");
        match MetaStore::open(&path) {
            Ok(store) => return store,
            Err(err) => {
                tracing::warn!("元数据库打开失败,尝试删除损坏文件重建: {err}");
            }
        }
        // 尝试恢复:删除可能损坏的 redb 文件后重建。
        if let Err(err) = std::fs::remove_file(&path) {
            tracing::error!("无法删除损坏的元数据库文件 {path:?}: {err}");
            panic!(
                "元数据库文件损坏且无法自动删除,请手动删除后重启 / corrupted metadata db cannot be auto-removed: {path:?}"
            );
        }
        MetaStore::open(&path).unwrap_or_else(|err| {
            panic!(
                "删除损坏文件后仍无法创建元数据库 {path:?}: {err}。请检查磁盘空间与权限 / cannot create metadata db after recovery"
            )
        })
    }

    pub fn bootstrap() -> Arc<Self> {
        // 库级兜底警告:检测到全默认凭据时 warn。
        // 真正的"拒绝启动"在 server 入口 ensure_secure_startup() 执行(库本身不退出进程,
        // 以免集成测试无法构造 AppState)。
        let has_default_jwt = std::env::var("RUSTIO_JWT_SECRET").is_err();
        let has_default_root = std::env::var("RUSTIO_ROOT_USER").is_err()
            && std::env::var("MINIO_ROOT_USER").is_err();
        let has_default_console = std::env::var("RUSTIO_CONSOLE_PASSWORD").is_err();
        if has_default_jwt && has_default_root && has_default_console {
            tracing::warn!(
                "⚠ 使用默认凭据启动(admin/rustio-admin)。生产环境请设置 RUSTIO_JWT_SECRET / RUSTIO_ROOT_USER / RUSTIO_ROOT_PASSWORD / RUSTIO_CONSOLE_PASSWORD"
            );
        }

        let (events, _) = broadcast::channel(512);
        let now = Utc::now();
        let data_dir = std::env::var("RUSTIO_DATA_DIR")
            .or_else(|_| std::env::var("MINIO_VOLUMES"))
            .map(|raw| {
                // Compatible volume env may contain multiple paths; v1 uses the first one.
                raw.split_whitespace()
                    .next()
                    .unwrap_or("./data")
                    .to_string()
            })
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        let _ = std::fs::create_dir_all(&data_dir);
        let data_disks = Self::resolve_data_disks(&data_dir);
        for disk in &data_disks {
            let _ = std::fs::create_dir_all(disk);
        }

        let cluster_config = crate::state::cluster::ClusterConfig::parse();
        let local_node_id = cluster_config.local_node_id;
        let mut cluster_peers = HashMap::new();
        if cluster_config.is_cluster() {
            let mut disks = Vec::new();
            for (idx, path) in data_disks.iter().enumerate() {
                disks.push(crate::state::cluster::ClusterDiskInfo {
                    global_id: cluster_config.global_disk_id(idx),
                    local_index: idx,
                    local_path: path.clone(),
                });
            }
            cluster_peers.insert(
                local_node_id,
                crate::state::cluster::ClusterPeerInfo {
                    node_id: local_node_id,
                    node_name: cluster_config.local_node_name.clone(),
                    api_addr: cluster_config.local_api_addr.clone(),
                    zone: cluster_config.local_zone.clone(),
                    disks,
                    draining: false,
                },
            );
            // Seed peers:同构集群假设(磁盘数与本地相同)。远程节点的 local_path 仅占位,
            // 远程节点收到分片 RPC 后用自身 resolve_data_disks + disk_index 重建真实路径。
            let local_disk_count = data_disks.len();
            for (&seed_id, seed_addr) in &cluster_config.seed_peers {
                if seed_id == local_node_id {
                    continue;
                }
                let seed_name = format!("node-{seed_id}");
                let disks = (0..local_disk_count)
                    .map(|idx| crate::state::cluster::ClusterDiskInfo {
                        global_id: format!("{seed_name}-disk-{idx}"),
                        local_index: idx,
                        local_path: PathBuf::new(), // 远程占位
                    })
                    .collect();
                cluster_peers.insert(
                    seed_id,
                    crate::state::cluster::ClusterPeerInfo {
                        node_id: seed_id,
                        node_name: seed_name,
                        api_addr: seed_addr.clone(),
                        zone: "unknown".to_string(),
                        disks,
                        draining: false,
                    },
                );
            }
        }

        let s3_access_key = std::env::var("RUSTIO_ROOT_USER")
            .or_else(|_| std::env::var("MINIO_ROOT_USER"))
            .unwrap_or_else(|_| "rustioadmin".to_string());
        let s3_secret_key = std::env::var("RUSTIO_ROOT_PASSWORD")
            .or_else(|_| std::env::var("MINIO_ROOT_PASSWORD"))
            .unwrap_or_else(|_| "rustioadmin".to_string());

        let console_user =
            std::env::var("RUSTIO_CONSOLE_USER").unwrap_or_else(|_| "admin".to_string());
        let console_password =
            std::env::var("RUSTIO_CONSOLE_PASSWORD").unwrap_or_else(|_| "rustio-admin".to_string());

        let mut credentials = HashMap::new();
        credentials.insert(
            console_user.clone(),
            LocalCredential {
                password: console_password,
                role: "admin".to_string(),
            },
        );
        if console_user != "admin" {
            credentials.insert(
                "admin".to_string(),
                LocalCredential {
                    password: "rustio-admin".to_string(),
                    role: "admin".to_string(),
                },
            );
        }

        let remote_tiers = Self::load_remote_tiers(&data_dir);
        let mut buckets = HashMap::new();
        let mut bucket_object_locks = HashMap::new();
        let mut bucket_retentions = HashMap::new();
        let mut bucket_legal_holds = HashMap::new();
        let mut bucket_notifications = HashMap::new();
        let mut bucket_lifecycle_rules = HashMap::new();
        let mut bucket_acls = HashMap::new();
        let mut bucket_public_access_blocks = HashMap::new();
        let mut bucket_policies = HashMap::new();
        let mut bucket_cors_rules = HashMap::new();
        let mut bucket_tags = HashMap::new();
        let mut bucket_encryptions = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&data_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if !file_type.is_dir() {
                        continue;
                    }
                } else {
                    continue;
                }

                let name = entry.file_name().to_string_lossy().to_string();
                if name.is_empty() || name.starts_with('.') {
                    continue;
                }

                let bucket = BucketSpec {
                    name: name.clone(),
                    tenant_id: "default".to_string(),
                    versioning: true,
                    object_lock: false,
                    ilm_policy: None,
                    replication_policy: None,
                };
                buckets.insert(name.clone(), bucket.clone());
                bucket_object_locks.insert(
                    name.clone(),
                    BucketObjectLockConfig {
                        enabled: bucket.object_lock,
                        mode: "GOVERNANCE".to_string(),
                        default_retention_days: 30,
                    },
                );
                bucket_retentions.insert(
                    name.clone(),
                    BucketRetentionConfig {
                        enabled: false,
                        mode: "GOVERNANCE".to_string(),
                        duration_days: 30,
                    },
                );
                bucket_legal_holds.insert(name.clone(), BucketLegalHoldConfig { enabled: false });
                bucket_notifications.insert(name.clone(), Vec::new());
                bucket_acls.insert(
                    name.clone(),
                    BucketAclConfig {
                        acl: "private".to_string(),
                    },
                );
                bucket_public_access_blocks.insert(
                    name.clone(),
                    BucketPublicAccessBlockConfig {
                        block_public_acls: false,
                        ignore_public_acls: false,
                        block_public_policy: false,
                        restrict_public_buckets: false,
                    },
                );

                let notifications_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-notifications.json");
                if let Ok(bytes) = std::fs::read(&notifications_path) {
                    if let Ok(rules) = serde_json::from_slice::<Vec<BucketNotificationRule>>(&bytes)
                    {
                        bucket_notifications.insert(name.clone(), rules);
                    }
                }

                let lifecycle_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-lifecycle.json");
                if let Ok(bytes) = std::fs::read(&lifecycle_path) {
                    if let Ok(rules) = serde_json::from_slice::<Vec<BucketLifecycleRule>>(&bytes) {
                        bucket_lifecycle_rules.insert(name.clone(), rules);
                    }
                }

                let acl_path = entry.path().join(".rustio_meta").join("bucket-acl.json");
                if let Ok(bytes) = std::fs::read(&acl_path) {
                    if let Ok(acl) = serde_json::from_slice::<BucketAclConfig>(&bytes) {
                        bucket_acls.insert(name.clone(), acl);
                    }
                }

                let pab_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-public-access-block.json");
                if let Ok(bytes) = std::fs::read(&pab_path) {
                    if let Ok(pab) = serde_json::from_slice::<BucketPublicAccessBlockConfig>(&bytes)
                    {
                        bucket_public_access_blocks.insert(name.clone(), pab);
                    }
                }

                let policy_path = entry.path().join(".rustio_meta").join("bucket-policy.json");
                if let Ok(bytes) = std::fs::read(&policy_path) {
                    if let Ok(policy) = serde_json::from_slice::<Value>(&bytes) {
                        bucket_policies.insert(name.clone(), policy);
                    }
                }

                let cors_path = entry.path().join(".rustio_meta").join("bucket-cors.json");
                if let Ok(bytes) = std::fs::read(&cors_path) {
                    if let Ok(cors_rules) = serde_json::from_slice::<Vec<BucketCorsRule>>(&bytes) {
                        bucket_cors_rules.insert(name.clone(), cors_rules);
                    }
                }

                let tags_path = entry.path().join(".rustio_meta").join("bucket-tags.json");
                if let Ok(bytes) = std::fs::read(&tags_path) {
                    if let Ok(tags) = serde_json::from_slice::<Vec<BucketTag>>(&bytes) {
                        bucket_tags.insert(name.clone(), tags);
                    }
                }

                let encryption_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-encryption.json");
                if let Ok(bytes) = std::fs::read(&encryption_path) {
                    if let Ok(encryption) = serde_json::from_slice::<BucketEncryptionConfig>(&bytes)
                    {
                        bucket_encryptions.insert(name, encryption);
                    }
                }
            }
        }

        let security = Self::load_security_config(&data_dir);
        let cluster_config_history = Self::load_cluster_config_history(&data_dir, &security);
        let console_sessions = Self::load_console_sessions(&data_dir);

        let meta_store = Self::open_meta_store_or_recover(&data_dir);
        match meta_store.migrate_from_data_dir(&data_dir) {
            Ok(0) => {}
            Ok(count) => tracing::info!("已迁移 {count} 条对象元数据到 redb"),
            Err(err) => tracing::warn!("对象元数据迁移到 redb 失败: {err}"),
        }

        let state = Arc::new(Self {
            jwt_secret: std::env::var("RUSTIO_JWT_SECRET")
                .unwrap_or_else(|_| "rustio-dev-secret".to_string()),
            s3_access_key: s3_access_key.clone(),
            s3_secret_key: s3_secret_key.clone(),
            data_dir,
            data_disks,
            local_node_id,
            cluster_peers: RwLock::new(cluster_peers),
            membership_change_lock: tokio::sync::Mutex::new(()),
            architecture: ArchitectureTopology {
                version: "m0-architecture-aligned".to_string(),
                aligned_at: now,
                planes: vec![
                    PlaneTopology {
                        id: "control-plane".to_string(),
                        name: "控制平面".to_string(),
                        responsibilities: vec![
                            "管理 API".to_string(),
                            "访问控制与会话".to_string(),
                            "审计与配置治理".to_string(),
                        ],
                        components: vec![
                            PlaneComponent {
                                id: "admin-api".to_string(),
                                responsibility: "承载 /api/v1/* 控制接口".to_string(),
                                owner: "rustio-admin".to_string(),
                            },
                            PlaneComponent {
                                id: "auth-service".to_string(),
                                responsibility: "本地账号登录、JWT 签发与校验".to_string(),
                                owner: "rustio-admin/auth".to_string(),
                            },
                            PlaneComponent {
                                id: "audit-service".to_string(),
                                responsibility: "审计事件记录与导出".to_string(),
                                owner: "rustio-admin/state".to_string(),
                            },
                        ],
                    },
                    PlaneTopology {
                        id: "metadata-plane".to_string(),
                        name: "元数据平面".to_string(),
                        responsibilities: vec![
                            "桶/IAM/策略元数据".to_string(),
                            "版本与对象治理元数据".to_string(),
                            "集群配置快照".to_string(),
                        ],
                        components: vec![
                            PlaneComponent {
                                id: "bucket-metadata-store".to_string(),
                                responsibility: "桶治理与对象治理元数据".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "iam-metadata-store".to_string(),
                                responsibility: "用户、组、策略、服务账号、STS 会话".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "cluster-config-history".to_string(),
                                responsibility: "配置验证、应用、回滚历史".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                        ],
                    },
                    PlaneTopology {
                        id: "data-plane".to_string(),
                        name: "数据平面".to_string(),
                        responsibilities: vec![
                            "对象数据读写".to_string(),
                            "版本归档与分片上传".to_string(),
                            "S3 协议入口".to_string(),
                        ],
                        components: vec![
                            PlaneComponent {
                                id: "s3-gateway".to_string(),
                                responsibility: "根路径 S3 兼容接口与 SigV4 验签".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "object-store".to_string(),
                                responsibility: "本地文件对象存取与对象元数据缓存".to_string(),
                                owner: "rustio-admin/state".to_string(),
                            },
                            PlaneComponent {
                                id: "multipart-store".to_string(),
                                responsibility: "分片上传会话与分片清单维护".to_string(),
                                owner: "rustio-admin/state".to_string(),
                            },
                        ],
                    },
                    PlaneTopology {
                        id: "worker-plane".to_string(),
                        name: "任务平面".to_string(),
                        responsibilities: vec![
                            "复制状态与补偿队列".to_string(),
                            "后台任务编排".to_string(),
                            "告警规则触发与处理历史".to_string(),
                        ],
                        components: vec![
                            PlaneComponent {
                                id: "replication-worker".to_string(),
                                responsibility: "复制规则状态、站点切换、重试队列".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "job-orchestrator".to_string(),
                                responsibility: "heal/cancel 等后台任务状态机入口".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "alert-worker".to_string(),
                                responsibility: "告警规则评估触发与历史处理".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                        ],
                    },
                ],
            },
            credentials: RwLock::new(credentials),
            nodes: RwLock::new(vec![
                ClusterNode {
                    id: "node-a".to_string(),
                    hostname: "rustio-node-a".to_string(),
                    zone: "zone-1".to_string(),
                    online: true,
                    capacity_total_bytes: 10 * 1024 * 1024 * 1024 * 1024,
                    capacity_used_bytes: 3 * 1024 * 1024 * 1024 * 1024,
                    last_heartbeat: now,
                },
                ClusterNode {
                    id: "node-b".to_string(),
                    hostname: "rustio-node-b".to_string(),
                    zone: "zone-1".to_string(),
                    online: true,
                    capacity_total_bytes: 10 * 1024 * 1024 * 1024 * 1024,
                    capacity_used_bytes: 4 * 1024 * 1024 * 1024 * 1024,
                    last_heartbeat: now,
                },
                ClusterNode {
                    id: "node-c".to_string(),
                    hostname: "rustio-node-c".to_string(),
                    zone: "zone-2".to_string(),
                    online: true,
                    capacity_total_bytes: 10 * 1024 * 1024 * 1024 * 1024,
                    capacity_used_bytes: 2 * 1024 * 1024 * 1024 * 1024,
                    last_heartbeat: now,
                },
            ]),
            quotas: RwLock::new(vec![
                ClusterQuota {
                    tenant: "default".to_string(),
                    hard_limit_bytes: 20 * 1024 * 1024 * 1024 * 1024,
                    used_bytes: 7 * 1024 * 1024 * 1024 * 1024,
                },
                ClusterQuota {
                    tenant: "analytics".to_string(),
                    hard_limit_bytes: 8 * 1024 * 1024 * 1024 * 1024,
                    used_bytes: 2 * 1024 * 1024 * 1024 * 1024,
                },
            ]),
            tenants: RwLock::new(vec![
                TenantSpec {
                    id: "default".to_string(),
                    display_name: "默认租户".to_string(),
                    owner_group: "platform-admins".to_string(),
                    project_id: Some("default".to_string()),
                    project_name: Some("默认租户".to_string()),
                    domain_id: Some("default".to_string()),
                    domain_name: Some("Default".to_string()),
                    enabled: true,
                    status: "active".to_string(),
                    hard_limit_bytes: 20 * 1024 * 1024 * 1024 * 1024,
                    used_bytes: 7 * 1024 * 1024 * 1024 * 1024,
                    created_at: now,
                    updated_at: now,
                    labels: HashMap::from([
                        ("env".to_string(), "prod".to_string()),
                        ("tier".to_string(), "gold".to_string()),
                    ]),
                },
                TenantSpec {
                    id: "analytics".to_string(),
                    display_name: "分析租户".to_string(),
                    owner_group: "platform-admins".to_string(),
                    project_id: Some("analytics".to_string()),
                    project_name: Some("分析租户".to_string()),
                    domain_id: Some("default".to_string()),
                    domain_name: Some("Default".to_string()),
                    enabled: true,
                    status: "active".to_string(),
                    hard_limit_bytes: 8 * 1024 * 1024 * 1024 * 1024,
                    used_bytes: 2 * 1024 * 1024 * 1024 * 1024,
                    created_at: now,
                    updated_at: now,
                    labels: HashMap::from([
                        ("env".to_string(), "prod".to_string()),
                        ("tier".to_string(), "silver".to_string()),
                    ]),
                },
            ]),
            diagnostics: RwLock::new(vec![]),
            cluster_config_history: RwLock::new(cluster_config_history),
            users: RwLock::new({
                let mut users = vec![IamUser {
                    username: console_user.clone(),
                    display_name: "RustIO Admin".to_string(),
                    role: "admin".to_string(),
                    enabled: true,
                    created_at: now,
                }];
                if console_user != "admin" {
                    users.push(IamUser {
                        username: "admin".to_string(),
                        display_name: "RustIO Legacy Admin".to_string(),
                        role: "admin".to_string(),
                        enabled: true,
                        created_at: now,
                    });
                }
                users
            }),
            groups: RwLock::new(vec![IamGroup {
                name: "platform-admins".to_string(),
                members: {
                    let mut members = vec![console_user.clone()];
                    if console_user != "admin" {
                        members.push("admin".to_string());
                    }
                    members
                },
            }]),
            policies: RwLock::new(vec![IamPolicy {
                name: "cluster-admin".to_string(),
                document: json!({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["*"],
                        "Resource": ["*"]
                    }]
                }),
                attached_to: {
                    let mut attached = vec![console_user.clone()];
                    if console_user != "admin" {
                        attached.push("admin".to_string());
                    }
                    attached
                },
            }]),
            service_accounts: RwLock::new(vec![rustio_core::ServiceAccount {
                access_key: "sa-bootstrap".to_string(),
                secret_key: "sa-bootstrap-secret".to_string(),
                owner: "admin".to_string(),
                created_at: now,
                status: "enabled".to_string(),
            }]),
            admin_sessions: RwLock::new(console_sessions),
            sts_sessions: RwLock::new(vec![StsSession {
                session_id: Uuid::new_v4().to_string(),
                principal: "admin".to_string(),
                access_key: "sts-bootstrap-ak".to_string(),
                secret_key: "sts-bootstrap-sk".to_string(),
                session_token: Uuid::new_v4().to_string(),
                provider: "manual".to_string(),
                role_arn: None,
                session_name: Some("bootstrap".to_string()),
                session_policy: None,
                subject: None,
                audience: None,
                status: "active".to_string(),
                issued_at: now,
                expires_at: now + Duration::hours(1),
            }]),
            buckets: RwLock::new(buckets),
            remote_tiers: RwLock::new(remote_tiers),
            bucket_object_locks: RwLock::new(bucket_object_locks),
            bucket_retentions: RwLock::new(bucket_retentions),
            bucket_legal_holds: RwLock::new(bucket_legal_holds),
            bucket_notifications: RwLock::new(bucket_notifications),
            bucket_lifecycle_rules: RwLock::new(bucket_lifecycle_rules),
            bucket_acls: RwLock::new(bucket_acls),
            bucket_public_access_blocks: RwLock::new(bucket_public_access_blocks),
            bucket_policies: RwLock::new(bucket_policies),
            bucket_cors_rules: RwLock::new(bucket_cors_rules),
            bucket_tags: RwLock::new(bucket_tags),
            bucket_encryptions: RwLock::new(bucket_encryptions),
            replications: RwLock::new(vec![]),
            site_replications: RwLock::new(vec![
                SiteReplicationStatus {
                    site_id: "dr-site-a".to_string(),
                    endpoint: "https://dr-site-a.example.internal".to_string(),
                    role: "primary".to_string(),
                    preferred_primary: true,
                    state: "healthy".to_string(),
                    lag_seconds: 0,
                    managed_buckets: 3,
                    last_sync_at: now,
                    bootstrap_state: "ready".to_string(),
                    joined_at: Some(now),
                    last_resync_at: Some(now),
                    last_reconcile_at: Some(now),
                    pending_resync_items: 0,
                    drifted_buckets: 0,
                    topology_version: 1,
                    last_error: None,
                },
                SiteReplicationStatus {
                    site_id: "dr-site-b".to_string(),
                    endpoint: "https://dr-site-b.example.internal".to_string(),
                    role: "secondary".to_string(),
                    preferred_primary: false,
                    state: "healthy".to_string(),
                    lag_seconds: 12,
                    managed_buckets: 3,
                    last_sync_at: now - Duration::seconds(12),
                    bootstrap_state: "ready".to_string(),
                    joined_at: Some(now),
                    last_resync_at: Some(now - Duration::seconds(12)),
                    last_reconcile_at: Some(now - Duration::seconds(12)),
                    pending_resync_items: 0,
                    drifted_buckets: 0,
                    topology_version: 1,
                    last_error: None,
                },
            ]),
            replication_backlog: RwLock::new(vec![]),
            replication_checkpoints: RwLock::new(HashMap::new()),
            replication_sequence: AtomicU64::new(1),
            alert_rules: RwLock::new(vec![
                AlertRule {
                    id: "rule-capacity-high".to_string(),
                    name: "容量使用率过高".to_string(),
                    metric: "cluster.capacity.used_ratio".to_string(),
                    condition: ">=".to_string(),
                    threshold: 0.85,
                    window_minutes: 5,
                    severity: "critical".to_string(),
                    enabled: true,
                    channels: vec!["channel-webhook-main".to_string()],
                    last_triggered_at: None,
                },
                AlertRule {
                    id: "rule-repl-lag".to_string(),
                    name: "复制延迟超阈值".to_string(),
                    metric: "replication.lag.seconds".to_string(),
                    condition: ">=".to_string(),
                    threshold: 300.0,
                    window_minutes: 10,
                    severity: "warning".to_string(),
                    enabled: true,
                    channels: vec!["channel-email-ops".to_string()],
                    last_triggered_at: None,
                },
            ]),
            alert_channels: RwLock::new(vec![
                AlertChannel {
                    id: "channel-webhook-main".to_string(),
                    name: "主 webhook".to_string(),
                    kind: "webhook".to_string(),
                    endpoint: "https://hooks.example.internal/rustio/alerts".to_string(),
                    headers: HashMap::new(),
                    payload_template: None,
                    header_template: HashMap::new(),
                    enabled: true,
                    status: "healthy".to_string(),
                    last_checked_at: now,
                    error: None,
                },
                AlertChannel {
                    id: "channel-email-ops".to_string(),
                    name: "运维邮件组".to_string(),
                    kind: "email".to_string(),
                    endpoint: "ops@example.internal".to_string(),
                    headers: HashMap::new(),
                    payload_template: None,
                    header_template: HashMap::new(),
                    enabled: true,
                    status: "healthy".to_string(),
                    last_checked_at: now,
                    error: None,
                },
            ]),
            alert_silences: RwLock::new(vec![]),
            alert_escalations: RwLock::new(vec![
                AlertEscalationPolicy {
                    id: "escalation-critical".to_string(),
                    name: "严重告警 5 分钟升级".to_string(),
                    severity: "critical".to_string(),
                    wait_minutes: 5,
                    channels: vec![
                        "channel-webhook-main".to_string(),
                        "channel-email-ops".to_string(),
                    ],
                    enabled: true,
                },
                AlertEscalationPolicy {
                    id: "escalation-warning".to_string(),
                    name: "警告告警 15 分钟升级".to_string(),
                    severity: "warning".to_string(),
                    wait_minutes: 15,
                    channels: vec!["channel-email-ops".to_string()],
                    enabled: true,
                },
            ]),
            alert_history: RwLock::new(vec![
                AlertHistoryEntry {
                    id: "history-boot-1".to_string(),
                    rule_id: Some("rule-capacity-high".to_string()),
                    rule_name: Some("容量使用率过高".to_string()),
                    severity: "critical".to_string(),
                    status: "resolved".to_string(),
                    message: "节点容量瞬时峰值已回落至阈值以下".to_string(),
                    triggered_at: now - Duration::minutes(30),
                    source: "rule-engine".to_string(),
                    assignee: Some("admin".to_string()),
                    claimed_at: Some(now - Duration::minutes(29)),
                    acknowledged_by: Some("admin".to_string()),
                    acknowledged_at: Some(now - Duration::minutes(28)),
                    resolved_by: Some("admin".to_string()),
                    resolved_at: Some(now - Duration::minutes(26)),
                    details: json!({
                        "value": 0.91,
                        "threshold": 0.85
                    }),
                },
                AlertHistoryEntry {
                    id: "history-boot-2".to_string(),
                    rule_id: Some("rule-repl-lag".to_string()),
                    rule_name: Some("复制延迟超阈值".to_string()),
                    severity: "warning".to_string(),
                    status: "firing".to_string(),
                    message: "跨站复制延迟持续超过 300 秒".to_string(),
                    triggered_at: now - Duration::minutes(8),
                    source: "rule-engine".to_string(),
                    assignee: None,
                    claimed_at: None,
                    acknowledged_by: None,
                    acknowledged_at: None,
                    resolved_by: None,
                    resolved_at: None,
                    details: json!({
                        "value": 420,
                        "threshold": 300
                    }),
                },
            ]),
            alert_delivery_queue: RwLock::new(vec![]),
            security: RwLock::new(security),
            oidc_auth_requests: RwLock::new(HashMap::new()),
            oidc_completed_logins: RwLock::new(HashMap::new()),
            audits: RwLock::new(vec![]),
            jobs: RwLock::new(vec![JobStatus {
                id: "job-heal-001".to_string(),
                kind: "heal".to_string(),
                status: "idle".to_string(),
                priority: 3,
                bucket: None,
                object_key: None,
                site_id: None,
                idempotency_key: String::new(),
                attempt: 0,
                lease_owner: None,
                lease_until: None,
                checkpoint: None,
                last_error: None,
                payload: json!({}),
                progress: 0.0,
                created_at: now,
                updated_at: now,
                key: None,
                version_id: None,
                target: Some("cluster".to_string()),
                affected_disks: vec![],
                missing_shards: 0,
                corrupted_shards: 0,
                started_at: None,
                finished_at: None,
                attempts: 0,
                max_attempts: 0,
                next_attempt_at: None,
                error: None,
                dedupe_key: None,
                source: Some("bootstrap".to_string()),
                details: Value::Null,
            }]),
            object_access_heat: RwLock::new(HashMap::new()),
            storage_governance: RwLock::new(StorageGovernanceRuntimeState::default()),
            meta_store,
            login_rate_limiter: crate::routes::rate_limit::LoginRateLimiter::default_policy(),
            multipart_uploads: RwLock::new(HashMap::new()),
            last_request_activity_at: AtomicI64::new(Utc::now().timestamp()),
            last_memory_trim_at: AtomicI64::new(0),
            events,
            meta_raft: std::sync::OnceLock::new(),
            meta_raft_app: std::sync::Arc::new(std::sync::OnceLock::new()),
        });
        state.restore_replication_runtime_state();
        state.start_background_workers();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let state_clone = Arc::clone(&state);
            handle.spawn(async move {
                state_clone.restore_replication_runtime_state();
            });
        }
        state
    }
}
