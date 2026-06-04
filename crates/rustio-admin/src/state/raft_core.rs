//! 会话运行时与 Raft 核心状态、快照构建

use super::*;

impl AppState {
    pub fn internal_control_token() -> String {
        std::env::var("RUSTIO_INTERNAL_TOKEN").unwrap_or_else(|_| "rustio-internal-token".to_string())
    }

    pub async fn upsert_console_session_runtime(&self, session: ConsoleSession) -> Result<(), String> {
        let snapshot = {
            let mut sessions = self.admin_sessions.write().await;
            sessions.retain(|item| item.session_id != session.session_id);
            sessions.push(session);
            sessions.clone()
        };
        Self::persist_console_sessions_snapshot(&self.data_dir, &snapshot)
    }

    pub async fn delete_console_session_runtime(&self, session_id: &str) -> Result<(), String> {
        let snapshot = {
            let mut sessions = self.admin_sessions.write().await;
            sessions.retain(|item| item.session_id != session_id);
            sessions.clone()
        };
        Self::persist_console_sessions_snapshot(&self.data_dir, &snapshot)
    }

    pub async fn broadcast_console_session_runtime(&self, session: &ConsoleSession) {
        if !Self::metadata_network_enabled() { return; }
        let endpoints = Self::metadata_peer_endpoints();
        if endpoints.is_empty() { return; }
        let local_peer_id = Self::metadata_local_peer_id();
        let internal_token = Self::internal_control_token();
        let client = Client::builder().timeout(std::time::Duration::from_secs(3)).build().unwrap_or_else(|_| Client::new());
        for (peer_id, endpoint) in endpoints {
            if peer_id == local_peer_id { continue; }
            let url = format!("{endpoint}/api/v1/internal/auth/sessions/sync");
            let _ = client.post(url).header("x-rustio-internal-token", &internal_token).json(session).send().await;
        }
    }

    pub async fn broadcast_console_session_delete_runtime(&self, session_id: &str) {
        if !Self::metadata_network_enabled() { return; }
        let endpoints = Self::metadata_peer_endpoints();
        if endpoints.is_empty() { return; }
        let local_peer_id = Self::metadata_local_peer_id();
        let internal_token = Self::internal_control_token();
        let client = Client::builder().timeout(std::time::Duration::from_secs(3)).build().unwrap_or_else(|_| Client::new());
        for (peer_id, endpoint) in endpoints {
            if peer_id == local_peer_id { continue; }
            let url = format!("{endpoint}/api/v1/internal/auth/sessions/sync/{session_id}");
            let _ = client.delete(url).header("x-rustio-internal-token", &internal_token).send().await;
        }
    }

    pub(crate) fn metadata_peer_endpoints() -> HashMap<String, String> {
        let mut endpoints = HashMap::new();
        let raw = std::env::var("RUSTIO_METADATA_RAFT_PEERS").unwrap_or_default();
        for item in raw.split(',') {
            let token = item.trim();
            if token.is_empty() { continue; }
            let mut pair = token.splitn(2, '=');
            let Some(peer_id) = pair.next().map(str::trim).filter(|v| !v.is_empty()) else { continue; };
            let Some(endpoint) = pair.next().map(str::trim).filter(|v| !v.is_empty()) else { continue; };
            endpoints.insert(peer_id.to_string(), endpoint.to_string());
        }
        endpoints
    }

    pub(crate) fn bootstrap_metadata_raft(data_dir: &Path) -> MetadataRaftState {
        let raft_root = data_dir.join(".rustio_meta_raft");
        let _ = std::fs::create_dir_all(&raft_root);
        let peer_endpoints = Self::metadata_peer_endpoints();
        let peers = (1..=3).map(|idx| {
            let peer_id = format!("meta-{idx}");
            let peer_dir = raft_root.join(&peer_id);
            let _ = std::fs::create_dir_all(&peer_dir);
            MetadataRaftPeer { endpoint: peer_endpoints.get(&peer_id).cloned(), id: peer_id, path: peer_dir, online: true, match_index: 0, next_index: 1, last_index: 0 }
        }).collect::<Vec<_>>();
        MetadataRaftState {
            cluster_id: "raft-meta-cluster".to_string(), leader_id: "meta-1".to_string(), term: 1,
            voted_for: None, commit_index: 0, last_commit_term: 0,
            last_heartbeat_at: Some(Utc::now()), last_election_at: None, last_quorum_at: Some(Utc::now()),
            membership_phase: "stable".to_string(), joint_old_members: Vec::new(), joint_new_members: Vec::new(),
            last_snapshot_hash: String::new(), last_error: None, last_commit_at: None, peers,
        }
    }

    pub async fn export_metadata_raft_sync_request(&self, reason: &str) -> Result<MetadataRaftSyncRequest, String> {
        let snapshot = self.build_metadata_snapshot().await;
        let raft = self.metadata_raft.read().await;
        Ok(MetadataRaftSyncRequest {
            cluster_id: raft.cluster_id.clone(), peer_id: Self::metadata_local_peer_id(),
            entry: MetadataRaftLogEntry { index: raft.commit_index, term: raft.term, reason: reason.to_string(), written_at: Utc::now(), snapshot_hash: raft.last_snapshot_hash.clone() },
            prev_log_index: 0, prev_log_term: 0, install_snapshot: true, leader_commit: raft.commit_index, snapshot,
        })
    }

    pub(crate) async fn build_metadata_snapshot(&self) -> MetadataRaftSnapshot {
        let mut buckets = self.buckets.read().await.values().cloned().collect::<Vec<_>>();
        buckets.sort_by(|left, right| left.name.cmp(&right.name));
        let remote_tiers = Self::sorted_map_entries(&self.remote_tiers.read().await.clone());
        let bucket_object_locks = Self::sorted_map_entries(&self.bucket_object_locks.read().await.clone());
        let bucket_retentions = Self::sorted_map_entries(&self.bucket_retentions.read().await.clone());
        let bucket_legal_holds = Self::sorted_map_entries(&self.bucket_legal_holds.read().await.clone());
        let bucket_notifications = Self::sorted_map_entries(&self.bucket_notifications.read().await.clone());
        let bucket_lifecycle_rules = Self::sorted_map_entries(&self.bucket_lifecycle_rules.read().await.clone());
        let bucket_acls = Self::sorted_map_entries(&self.bucket_acls.read().await.clone());
        let bucket_public_access_blocks = Self::sorted_map_entries(&self.bucket_public_access_blocks.read().await.clone());
        let bucket_policies = Self::sorted_map_entries(&self.bucket_policies.read().await.clone());
        let bucket_cors_rules = Self::sorted_map_entries(&self.bucket_cors_rules.read().await.clone());
        let bucket_tags = Self::sorted_map_entries(&self.bucket_tags.read().await.clone());
        let bucket_encryptions = Self::sorted_map_entries(&self.bucket_encryptions.read().await.clone());
        let mut iam_users = self.users.read().await.clone(); iam_users.sort_by(|l, r| l.username.cmp(&r.username));
        let credentials = Self::sorted_map_entries(&self.credentials.read().await.clone());
        let mut iam_groups = self.groups.read().await.clone(); iam_groups.sort_by(|l, r| l.name.cmp(&r.name));
        let mut iam_policies = self.policies.read().await.clone(); iam_policies.sort_by(|l, r| l.name.cmp(&r.name));
        let mut service_accounts = self.service_accounts.read().await.clone(); service_accounts.sort_by(|l, r| l.access_key.cmp(&r.access_key));
        let mut admin_sessions = self.admin_sessions.read().await.clone(); admin_sessions.sort_by(|l, r| l.session_id.cmp(&r.session_id));
        let mut sts_sessions = self.sts_sessions.read().await.clone(); sts_sessions.sort_by(|l, r| l.session_id.cmp(&r.session_id));
        let mut replications = self.replications.read().await.clone();
        replications.sort_by(|l, r| l.source_bucket.cmp(&r.source_bucket).then_with(|| l.target_site.cmp(&r.target_site)).then_with(|| l.rule_id.cmp(&r.rule_id)));
        let mut site_replications = self.site_replications.read().await.clone(); site_replications.sort_by(|l, r| l.site_id.cmp(&r.site_id));
        let mut replication_backlog = self.replication_backlog.read().await.clone(); replication_backlog.sort_by(|l, r| l.id.cmp(&r.id));
        let replication_checkpoints = Self::sorted_map_entries(&self.replication_checkpoints.read().await.clone());
        let cluster_config_history = self.cluster_config_history.read().await.clone();
        let security = self.security.read().await.clone();
        let mut jobs = self.jobs.read().await.clone(); jobs.sort_by(|l, r| l.id.cmp(&r.id));
        MetadataRaftSnapshot {
            generated_at: Utc::now(), buckets, remote_tiers, bucket_object_locks, bucket_retentions,
            bucket_legal_holds, bucket_notifications, bucket_lifecycle_rules, bucket_acls,
            bucket_public_access_blocks, bucket_policies, bucket_cors_rules, bucket_tags, bucket_encryptions,
            objects: Vec::new(), credentials, iam_users, iam_groups, iam_policies, service_accounts,
            admin_sessions, sts_sessions, replications, site_replications, replication_backlog,
            replication_checkpoints, cluster_config_history, security, jobs,
        }
    }

    pub async fn persist_replication_runtime_state(&self) {
        let runtime = ReplicationRuntimeState {
            version: 1,
            sequence: self.replication_sequence.load(Ordering::SeqCst),
            backlog: self.replication_backlog.read().await.clone(),
            checkpoints: self.replication_checkpoints.read().await.clone(),
        };
        let path = self.replication_state_path();
        if let Some(parent) = path.parent() { let _ = std::fs::create_dir_all(parent); }
        if let Ok(bytes) = serde_json::to_vec_pretty(&runtime) {
            let temp_path = path.with_extension("tmp");
            if std::fs::write(&temp_path, bytes).is_ok() { let _ = std::fs::rename(temp_path, path); }
        }
    }

    pub(crate) fn restore_replication_runtime_state(&self) {
        let state_path = self.replication_state_path();
        let bytes = match std::fs::read(&state_path) { Ok(b) => b, Err(_) => return };
        let runtime = match serde_json::from_slice::<ReplicationRuntimeState>(&bytes) { Ok(v) => v, Err(_) => return };
        if let Ok(mut backlog) = self.replication_backlog.try_write() { *backlog = runtime.backlog; }
        if let Ok(mut checkpoints) = self.replication_checkpoints.try_write() { *checkpoints = runtime.checkpoints; }
        let mut next_sequence = runtime.sequence.max(1);
        if let Ok(backlog) = self.replication_backlog.try_read() {
            for item in backlog.iter() { next_sequence = next_sequence.max(item.checkpoint.saturating_add(1)); }
        }
        if let Ok(checkpoints) = self.replication_checkpoints.try_read() {
            for checkpoint in checkpoints.values() { next_sequence = next_sequence.max(checkpoint.saturating_add(1)); }
        }
        self.replication_sequence.store(next_sequence.max(1), Ordering::SeqCst);
    }

    pub(crate) fn replication_state_path(&self) -> PathBuf {
        self.replication_root_dir().join("runtime-state.json")
    }

    pub(crate) fn sorted_map_entries<T: Clone>(map: &HashMap<String, T>) -> Vec<(String, T)> {
        let mut entries = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
        entries.sort_by(|l, r| l.0.cmp(&r.0));
        entries
    }

    pub(crate) fn hash_json(value: &impl Serialize) -> Result<String, String> {
        let bytes = serde_json::to_vec(value).map_err(|err| err.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    #[allow(dead_code)]
    pub(crate) fn metadata_snapshot_hash(snapshot: &MetadataRaftSnapshot) -> Result<String, String> {        let mut canonical = snapshot.clone();
        canonical.generated_at = DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH);
        Self::hash_json(&canonical)
    }

    pub async fn elect_metadata_leader(&self, leader_id: &str) -> Result<MetadataRaftStatus, String> {
        let mut raft = self.metadata_raft.write().await;
        raft.leader_id = leader_id.to_string();
        Ok(MetadataRaftStatus {
            cluster_id: raft.cluster_id.clone(), leader_id: raft.leader_id.clone(), term: raft.term,
            quorum: 1, online_peers: 1, commit_index: raft.commit_index,
            last_error: None, last_commit_at: None, membership_phase: "stable".to_string(),
            joint_old_members: vec![], joint_new_members: vec![], joint_elapsed_seconds: None,
            joint_timeout_seconds: 0, peers: raft.peers.clone(),
        })
    }

    pub async fn process_metadata_raft_heartbeat_once(&self) {}
    pub async fn process_metadata_membership_watchdog_once(&self) {}
}

#[allow(dead_code)]
pub(crate) fn metadata_peer_next_index_default() -> u64 { 1 }
