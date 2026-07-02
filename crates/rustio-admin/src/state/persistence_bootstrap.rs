//! 磁盘持久化加载/保存与 bootstrap 初始化

use super::*;

/// 查询挂载路径所在文件系统的总容量/已用容量(字节)。
/// 路径不存在或系统调用失败时返回 `(0, 0)`,由调用方据此判断该磁盘不可用。
fn query_real_disk_capacity(path: &Path) -> (u64, u64) {
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return (0, 0);
    };
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr() as *const libc::c_char, &mut stat) != 0 {
            return (0, 0);
        }
        let block_size = stat.f_frsize as u64;
        let total = block_size.saturating_mul(stat.f_blocks as u64);
        let free = block_size.saturating_mul(stat.f_bavail as u64);
        (total, total.saturating_sub(free))
    }
}

/// 本机主机名;获取失败(极少见)时回退到 `local_node_name`。
fn resolve_local_hostname(fallback: &str) -> String {
    let mut buf = [0u8; 256];
    unsafe {
        if libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(name) = std::str::from_utf8(&buf[..end]) {
                if !name.is_empty() {
                    return name.to_string();
                }
            }
        }
    }
    fallback.to_string()
}

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

    pub(crate) fn iam_state_path(data_dir: &Path) -> PathBuf {
        data_dir.join(".rustio_meta").join("iam-state.json")
    }

    /// 从盘加载持久化的 IAM 身份态(凭据/用户/组/策略/服务账号)。
    /// 缺失或损坏时返回 None,由调用方回退到环境变量种子默认值。
    pub(crate) fn load_iam_state(data_dir: &Path) -> Option<PersistedIamState> {
        let path = Self::iam_state_path(data_dir);
        std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<PersistedIamState>(&bytes).ok())
    }

    /// 落盘 IAM 身份态。任何 IAM 变更(改密码/建删用户/组/策略/服务账号)提交后调用,
    /// 保证进程重启后从盘恢复,而非退回环境变量种子(否则改过的密码会在重启后丢失)。
    pub(crate) fn persist_iam_state_snapshot(
        data_dir: &Path,
        credentials: &HashMap<String, LocalCredential>,
        users: &[IamUser],
        groups: &[IamGroup],
        policies: &[IamPolicy],
        service_accounts: &[rustio_core::ServiceAccount],
    ) -> Result<(), String> {
        let path = Self::iam_state_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let mut credential_entries = credentials
            .iter()
            .map(|(username, credential)| (username.clone(), credential.clone()))
            .collect::<Vec<_>>();
        credential_entries.sort_by(|left, right| left.0.cmp(&right.0));
        let payload = PersistedIamState {
            credentials: credential_entries,
            users: users.to_vec(),
            groups: groups.to_vec(),
            policies: policies.to_vec(),
            service_accounts: service_accounts.to_vec(),
        };
        let bytes = serde_json::to_vec_pretty(&payload).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }


    /// 打开 redb 元数据库,若文件损坏则自动删除重建(元数据可从 bucket 目录扫描恢复)。
    fn open_meta_store_or_recover(data_dir: &Path) -> Result<MetaStore, String> {
        let path = data_dir.join(".rustio_meta.redb");
        match MetaStore::open(&path) {
            Ok(store) => return Ok(store),
            Err(err) => {
                tracing::warn!("元数据库打开失败,尝试删除损坏文件重建: {err}");
            }
        }
        // 尝试恢复:删除可能损坏的 redb 文件后重建。
        if let Err(err) = std::fs::remove_file(&path) {
            tracing::error!("无法删除损坏的元数据库文件 {path:?}: {err}");
            return Err(format!(
                "元数据库文件损坏且无法自动删除,请手动删除后重启 / corrupted metadata db cannot be auto-removed: {path:?}: {err}"
            ));
        }
        MetaStore::open(&path).map_err(|err| {
            format!(
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
        if let Err(err) = std::fs::create_dir_all(&data_dir) {
            tracing::error!(path = %data_dir.display(), error = %err, "无法创建数据目录 / cannot create data dir");
        }
        // 提前查询本机数据目录所在文件系统的真实容量;data_dir 随后会被 move 进
        // AppState 字面量,这里先算好留作 nodes 初始化使用,避免 use-after-move。
        let local_disk_capacity = query_real_disk_capacity(&data_dir);
        let data_disks = Self::resolve_data_disks(&data_dir);
        for disk in &data_disks {
            if let Err(err) = std::fs::create_dir_all(disk) {
                tracing::error!(path = %disk.display(), error = %err, "无法创建磁盘目录 / cannot create disk dir");
            }
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
                    group_id: cluster_config.local_group_id.clone(),
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
                        group_id: "default".to_string(),
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

        // 优先从盘恢复 IAM 身份态(凭据/用户/组/策略/服务账号),否则用上面的环境变量种子。
        // 缺失此步会导致:改密码等 IAM 变更只落会话、不落身份态,进程重启后退回种子密码。
        let persisted_iam = Self::load_iam_state(&data_dir);
        if let Some(persisted) = persisted_iam.as_ref() {
            credentials = persisted.credentials.iter().cloned().collect();
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
        let mut bucket_website_configs = HashMap::new();
        let mut bucket_accelerate_configs = HashMap::new();
        let mut bucket_logging_configs = HashMap::new();
        let mut bucket_request_payment_configs = HashMap::new();
        let mut bucket_analytics_configs: HashMap<String, Vec<BucketAnalyticsConfig>> = HashMap::new();
        let mut bucket_metrics_configs: HashMap<String, Vec<BucketMetricsConfig>> = HashMap::new();
        let mut bucket_inventory_configs: HashMap<String, Vec<BucketInventoryConfig>> = HashMap::new();
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
                    versioning_configured: true,
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

                let website_path = entry.path().join(".rustio_meta").join("bucket-website.json");
                if let Ok(bytes) = std::fs::read(&website_path) {
                    if let Ok(website) = serde_json::from_slice::<BucketWebsiteConfig>(&bytes) {
                        bucket_website_configs.insert(name.clone(), website);
                    }
                }

                let encryption_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-encryption.json");
                if let Ok(bytes) = std::fs::read(&encryption_path) {
                    if let Ok(encryption) = serde_json::from_slice::<BucketEncryptionConfig>(&bytes)
                    {
                        bucket_encryptions.insert(name.clone(), encryption);
                    }
                }

                let accelerate_path = entry.path().join(".rustio_meta").join("bucket-accelerate.json");
                if let Ok(bytes) = std::fs::read(&accelerate_path) {
                    if let Ok(cfg) = serde_json::from_slice::<BucketAccelerateConfig>(&bytes) {
                        bucket_accelerate_configs.insert(name.clone(), cfg);
                    }
                }

                let logging_path = entry.path().join(".rustio_meta").join("bucket-logging.json");
                if let Ok(bytes) = std::fs::read(&logging_path) {
                    if let Ok(cfg) = serde_json::from_slice::<BucketLoggingConfig>(&bytes) {
                        bucket_logging_configs.insert(name.clone(), cfg);
                    }
                }

                let reqpay_path = entry.path().join(".rustio_meta").join("bucket-request-payment.json");
                if let Ok(bytes) = std::fs::read(&reqpay_path) {
                    if let Ok(cfg) = serde_json::from_slice::<BucketRequestPaymentConfig>(&bytes) {
                        bucket_request_payment_configs.insert(name.clone(), cfg);
                    }
                }

                let analytics_path = entry.path().join(".rustio_meta").join("bucket-analytics.json");
                if let Ok(bytes) = std::fs::read(&analytics_path) {
                    if let Ok(cfgs) = serde_json::from_slice::<Vec<BucketAnalyticsConfig>>(&bytes) {
                        bucket_analytics_configs.insert(name.clone(), cfgs);
                    }
                }

                let metrics_path = entry.path().join(".rustio_meta").join("bucket-metrics.json");
                if let Ok(bytes) = std::fs::read(&metrics_path) {
                    if let Ok(cfgs) = serde_json::from_slice::<Vec<BucketMetricsConfig>>(&bytes) {
                        bucket_metrics_configs.insert(name.clone(), cfgs);
                    }
                }

                let inventory_path = entry.path().join(".rustio_meta").join("bucket-inventory.json");
                if let Ok(bytes) = std::fs::read(&inventory_path) {
                    if let Ok(cfgs) = serde_json::from_slice::<Vec<BucketInventoryConfig>>(&bytes) {
                        bucket_inventory_configs.insert(name, cfgs);
                    }
                }
            }
        }

        let security = Self::load_security_config(&data_dir);
        let cluster_config_history = Self::load_cluster_config_history(&data_dir, &security);
        let console_sessions = Self::load_console_sessions(&data_dir);

        let meta_store = Self::open_meta_store_or_recover(&data_dir).unwrap_or_else(|err| {
            tracing::error!("{err}");
            std::process::exit(1);
        });
        match meta_store.migrate_from_data_dir(&data_dir) {
            Ok(0) => {}
            Ok(count) => tracing::info!("已迁移 {count} 条对象元数据到 redb"),
            Err(err) => tracing::warn!("对象元数据迁移到 redb 失败: {err}"),
        }

        let state = Arc::new(Self {
            jwt_secret: std::env::var("RUSTIO_JWT_SECRET").unwrap_or_else(|_| {
                tracing::warn!("RUSTIO_JWT_SECRET 未设置,使用随机密钥(重启后失效,仅供开发) / RUSTIO_JWT_SECRET not set, using random key (dev only)");
                // UUID v4 拼接 4 次 = 128 字节随机密钥
                format!(
                    "{}{}{}{}",
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4()
                )
            }),
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
            nodes: RwLock::new({
                // 只初始化本机节点,容量取本机数据目录所在文件系统的实际值。
                // 集群模式下其余节点由 raft 成员变更时补入。
                let (capacity_total_bytes, capacity_used_bytes) = local_disk_capacity;
                vec![ClusterNode {
                    id: if cluster_config.is_cluster() {
                        cluster_config.local_node_name.clone()
                    } else {
                        "node-1".to_string()
                    },
                    hostname: resolve_local_hostname(&cluster_config.local_node_name),
                    zone: cluster_config.local_zone.clone(),
                    online: true,
                    capacity_total_bytes,
                    capacity_used_bytes,
                    last_heartbeat: now,
                }]
            }),
            quotas: RwLock::new(vec![]),
            tenants: RwLock::new(vec![]),
            diagnostics: RwLock::new(vec![]),
            cluster_config_history: RwLock::new(cluster_config_history),
            users: RwLock::new(match persisted_iam.as_ref() {
                Some(persisted) => persisted.users.clone(),
                None => {
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
                }
            }),
            groups: RwLock::new(persisted_iam.as_ref().map(|p| p.groups.clone()).unwrap_or_else(|| {
                vec![IamGroup {
                    name: "platform-admins".to_string(),
                    members: {
                        let mut members = vec![console_user.clone()];
                        if console_user != "admin" {
                            members.push("admin".to_string());
                        }
                        members
                    },
                }]
            })),
            policies: RwLock::new(persisted_iam.as_ref().map(|p| p.policies.clone()).unwrap_or_else(|| {
                vec![IamPolicy {
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
                }]
            })),
            service_accounts: RwLock::new(
                persisted_iam
                    .as_ref()
                    .map(|p| p.service_accounts.clone())
                    // 不预置固定密钥的服务账号(所有实例使用相同密钥属于安全隐患);
                    // 需要服务账号时由用户经 IAM 控制台创建,密钥随机生成。
                    .unwrap_or_default(),
            ),
            admin_sessions: RwLock::new(console_sessions),
            sts_sessions: RwLock::new(vec![]),
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
            bucket_website_configs: RwLock::new(bucket_website_configs),
            bucket_accelerate_configs: RwLock::new(bucket_accelerate_configs),
            bucket_logging_configs: RwLock::new(bucket_logging_configs),
            bucket_request_payment_configs: RwLock::new(bucket_request_payment_configs),
            bucket_analytics_configs: RwLock::new(bucket_analytics_configs),
            bucket_metrics_configs: RwLock::new(bucket_metrics_configs),
            bucket_inventory_configs: RwLock::new(bucket_inventory_configs),
            replications: RwLock::new(vec![]),
            // 站点复制需要用户经「复制与容灾」页面显式 bootstrap/join 后才会出现。
            site_replications: RwLock::new(vec![]),
            replication_backlog: RwLock::new(vec![]),
            replication_checkpoints: RwLock::new(HashMap::new()),
            replication_sequence: AtomicU64::new(1),
            // 默认监控规则模板;channels 留空,由用户在「告警」页面建好通道后自行挂上。
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
                    channels: vec![],
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
                    channels: vec![],
                    last_triggered_at: None,
                },
            ]),
            // 通知通道由用户自行配置。
            alert_channels: RwLock::new(vec![]),
            alert_silences: RwLock::new(vec![]),
            // 升级策略模板;同样不引用具体通道。
            alert_escalations: RwLock::new(vec![
                AlertEscalationPolicy {
                    id: "escalation-critical".to_string(),
                    name: "严重告警 5 分钟升级".to_string(),
                    severity: "critical".to_string(),
                    wait_minutes: 5,
                    channels: vec![],
                    enabled: true,
                },
                AlertEscalationPolicy {
                    id: "escalation-warning".to_string(),
                    name: "警告告警 15 分钟升级".to_string(),
                    severity: "warning".to_string(),
                    wait_minutes: 15,
                    channels: vec![],
                    enabled: true,
                },
            ]),
            alert_history: RwLock::new(vec![]),
            alert_delivery_queue: RwLock::new(vec![]),
            security: RwLock::new(security),
            oidc_auth_requests: RwLock::new(HashMap::new()),
            oidc_completed_logins: RwLock::new(HashMap::new()),
            audits: RwLock::new(vec![]),
            jobs: RwLock::new(vec![]),
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
            io_uring_bridge: if crate::io_uring_bridge::is_io_uring_available() {
                Some(crate::io_uring_bridge::IoUringBridge::new(
                    std::thread::available_parallelism()
                        .map(|n| n.get() / 2)
                        .unwrap_or(2)
                        .max(1),
                ))
            } else {
                None
            },
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
