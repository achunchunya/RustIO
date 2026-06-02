//! 会话运行时与 Raft 核心状态、快照构建

use super::*;

impl AppState {
    pub fn internal_control_token() -> String {
        std::env::var("RUSTIO_INTERNAL_TOKEN")
            .unwrap_or_else(|_| "rustio-internal-token".to_string())
    }

    pub async fn upsert_console_session_runtime(
        &self,
        session: ConsoleSession,
    ) -> Result<(), String> {
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
        if !Self::metadata_network_enabled() {
            return;
        }

        let endpoints = Self::metadata_peer_endpoints();
        if endpoints.is_empty() {
            return;
        }

        let local_peer_id = Self::metadata_local_peer_id();
        let internal_token = Self::internal_control_token();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());

        for (peer_id, endpoint) in endpoints {
            if peer_id == local_peer_id {
                continue;
            }

            let url = format!("{endpoint}/api/v1/internal/auth/sessions/sync");
            let _ = client
                .post(url)
                .header("x-rustio-internal-token", &internal_token)
                .json(session)
                .send()
                .await;
        }
    }

    pub async fn broadcast_console_session_delete_runtime(&self, session_id: &str) {
        if !Self::metadata_network_enabled() {
            return;
        }

        let endpoints = Self::metadata_peer_endpoints();
        if endpoints.is_empty() {
            return;
        }

        let local_peer_id = Self::metadata_local_peer_id();
        let internal_token = Self::internal_control_token();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());

        for (peer_id, endpoint) in endpoints {
            if peer_id == local_peer_id {
                continue;
            }

            let url = format!(
                "{endpoint}/api/v1/internal/auth/sessions/sync/{}",
                session_id
            );
            let _ = client
                .delete(url)
                .header("x-rustio-internal-token", &internal_token)
                .send()
                .await;
        }
    }

    pub(crate) fn metadata_peer_endpoints() -> HashMap<String, String> {
        let mut endpoints = HashMap::new();
        let raw = std::env::var("RUSTIO_METADATA_RAFT_PEERS").unwrap_or_default();
        for item in raw.split(',') {
            let token = item.trim();
            if token.is_empty() {
                continue;
            }
            let mut pair = token.splitn(2, '=');
            let Some(peer_id) = pair.next().map(str::trim).filter(|value| !value.is_empty()) else {
                continue;
            };
            let Some(endpoint) = pair.next().map(str::trim).filter(|value| !value.is_empty())
            else {
                continue;
            };
            endpoints.insert(peer_id.to_string(), endpoint.to_string());
        }
        endpoints
    }

    pub(crate) fn metadata_raft_root_dir(data_dir: &Path) -> PathBuf {
        data_dir.join(".rustio_meta_raft")
    }

    pub(crate) fn metadata_raft_state_path(data_dir: &Path) -> PathBuf {
        Self::metadata_raft_root_dir(data_dir).join("state.json")
    }

    pub(crate) fn load_metadata_raft_runtime_state(
        data_dir: &Path,
    ) -> Option<MetadataRaftRuntimeState> {
        let bytes = std::fs::read(Self::metadata_raft_state_path(data_dir)).ok()?;
        serde_json::from_slice::<MetadataRaftRuntimeState>(&bytes).ok()
    }

    pub(crate) fn metadata_raft_runtime_from_state(
        raft: &MetadataRaftState,
    ) -> MetadataRaftRuntimeState {
        MetadataRaftRuntimeState {
            version: 1,
            cluster_id: raft.cluster_id.clone(),
            leader_id: raft.leader_id.clone(),
            term: raft.term,
            voted_for: raft.voted_for.clone(),
            commit_index: raft.commit_index,
            last_commit_term: raft.last_commit_term,
            last_snapshot_hash: raft.last_snapshot_hash.clone(),
            last_error: raft.last_error.clone(),
            last_commit_at: raft.last_commit_at,
            last_heartbeat_at: raft.last_heartbeat_at,
            last_election_at: raft.last_election_at,
            last_quorum_at: raft.last_quorum_at,
            membership_phase: raft.membership_phase.clone(),
            joint_old_members: raft.joint_old_members.clone(),
            joint_new_members: raft.joint_new_members.clone(),
            peers: raft
                .peers
                .iter()
                .map(|peer| MetadataRaftRuntimePeer {
                    id: peer.id.clone(),
                    endpoint: peer.endpoint.clone(),
                    online: peer.online,
                    last_index: peer.last_index,
                    match_index: peer.match_index,
                    next_index: peer.next_index,
                })
                .collect(),
        }
    }

    pub(crate) fn persist_metadata_raft_state_inner(
        &self,
        raft: &MetadataRaftState,
    ) -> Result<(), String> {
        let runtime = Self::metadata_raft_runtime_from_state(raft);
        let path = Self::metadata_raft_state_path(&self.data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(&runtime).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(temp_path, path).map_err(|err| err.to_string())?;
        Ok(())
    }

    pub async fn persist_metadata_raft_state(&self) -> Result<(), String> {
        let raft = self.metadata_raft.read().await.clone();
        self.persist_metadata_raft_state_inner(&raft)
    }

    pub(crate) fn bootstrap_metadata_raft(data_dir: &Path) -> MetadataRaftState {
        let raft_root = Self::metadata_raft_root_dir(data_dir);
        let _ = std::fs::create_dir_all(&raft_root);
        let peer_endpoints = Self::metadata_peer_endpoints();
        let peers = (1..=3)
            .map(|idx| {
                let peer_id = format!("meta-{idx}");
                let peer_dir = raft_root.join(&peer_id);
                let _ = std::fs::create_dir_all(&peer_dir);
                MetadataRaftPeer {
                    endpoint: peer_endpoints.get(&peer_id).cloned(),
                    id: peer_id,
                    path: peer_dir,
                    online: true,
                    match_index: 0,
                    next_index: 1,
                    last_index: 0,
                }
            })
            .collect::<Vec<_>>();
        let mut state = MetadataRaftState {
            cluster_id: "raft-meta-cluster".to_string(),
            leader_id: "meta-1".to_string(),
            term: 1,
            voted_for: None,
            commit_index: 0,
            last_commit_term: 0,
            last_heartbeat_at: Some(Utc::now()),
            last_election_at: None,
            last_quorum_at: Some(Utc::now()),
            membership_phase: "stable".to_string(),
            joint_old_members: Vec::new(),
            joint_new_members: Vec::new(),
            last_snapshot_hash: String::new(),
            last_error: None,
            last_commit_at: None,
            peers,
        };

        if let Some(runtime) = Self::load_metadata_raft_runtime_state(data_dir) {
            if !runtime.cluster_id.trim().is_empty() {
                state.cluster_id = runtime.cluster_id;
            }
            if runtime.term > 0 {
                state.term = runtime.term;
            }
            state.voted_for = runtime.voted_for;
            state.commit_index = runtime.commit_index;
            state.last_commit_term = if runtime.last_commit_term == 0 && runtime.commit_index > 0 {
                state.term
            } else {
                runtime.last_commit_term
            };
            state.last_snapshot_hash = runtime.last_snapshot_hash;
            state.last_error = runtime.last_error;
            state.last_commit_at = runtime.last_commit_at;
            state.last_heartbeat_at = runtime.last_heartbeat_at.or(state.last_commit_at);
            state.last_election_at = runtime.last_election_at;
            state.last_quorum_at = runtime.last_quorum_at.or(state.last_heartbeat_at);
            if runtime.membership_phase == "joint" {
                state.membership_phase = "joint".to_string();
                state.joint_old_members = runtime.joint_old_members;
                state.joint_new_members = runtime.joint_new_members;
            }

            let mut merged = state
                .peers
                .iter()
                .map(|peer| (peer.id.clone(), peer.clone()))
                .collect::<HashMap<_, _>>();
            for peer in runtime.peers {
                if peer.id.trim().is_empty() {
                    continue;
                }
                let peer_id = peer.id.trim().to_string();
                let peer_dir = raft_root.join(&peer_id);
                let _ = std::fs::create_dir_all(&peer_dir);
                merged
                    .entry(peer_id.clone())
                    .and_modify(|item| {
                        item.online = peer.online;
                        item.last_index = peer.last_index;
                        item.match_index = peer.match_index.max(peer.last_index);
                        item.next_index = if peer.next_index == 0 {
                            item.match_index.saturating_add(1)
                        } else {
                            peer.next_index
                        };
                        if peer.endpoint.is_some() {
                            item.endpoint = peer.endpoint.clone();
                        }
                    })
                    .or_insert(MetadataRaftPeer {
                        id: peer_id,
                        path: peer_dir,
                        endpoint: peer.endpoint,
                        online: peer.online,
                        match_index: peer.match_index.max(peer.last_index),
                        next_index: if peer.next_index == 0 {
                            peer.last_index.saturating_add(1)
                        } else {
                            peer.next_index
                        },
                        last_index: peer.last_index,
                    });
            }
            state.peers = merged.into_values().collect::<Vec<_>>();
            state.peers.sort_by(|left, right| left.id.cmp(&right.id));
            if !runtime.leader_id.trim().is_empty()
                && state.peers.iter().any(|peer| peer.id == runtime.leader_id)
            {
                state.leader_id = runtime.leader_id;
            }
        }

        for peer in &mut state.peers {
            if let Some(endpoint) = peer_endpoints.get(&peer.id) {
                peer.endpoint = Some(endpoint.clone());
            }
            peer.match_index = peer.match_index.max(peer.last_index);
            if peer.next_index == 0 {
                peer.next_index = peer.match_index.saturating_add(1);
            }
        }
        if !state
            .peers
            .iter()
            .any(|peer| peer.id == state.leader_id && peer.online)
        {
            if let Some(leader) = state.peers.iter().find(|peer| peer.online) {
                state.leader_id = leader.id.clone();
            }
        }
        state.last_heartbeat_at = Some(Utc::now());
        state.last_quorum_at = state.last_quorum_at.or(state.last_heartbeat_at);
        if state.membership_phase != "joint"
            || state.joint_old_members.is_empty()
            || state.joint_new_members.is_empty()
        {
            state.membership_phase = "stable".to_string();
            state.joint_old_members.clear();
            state.joint_new_members.clear();
        }
        state
    }

    pub(crate) fn hash_json(value: &impl Serialize) -> Result<String, String> {
        let bytes = serde_json::to_vec(value).map_err(|err| err.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    pub(crate) fn metadata_snapshot_hash(
        snapshot: &MetadataRaftSnapshot,
    ) -> Result<String, String> {
        let mut canonical = snapshot.clone();
        canonical.generated_at = DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH);
        Self::hash_json(&canonical)
    }

    pub(crate) fn raft_last_commit_term(raft: &MetadataRaftState) -> u64 {
        if raft.last_commit_term == 0 && raft.commit_index > 0 {
            raft.term
        } else {
            raft.last_commit_term
        }
    }

    pub(crate) async fn send_metadata_raft_sync_request(
        client: &Client,
        url: &str,
        internal_token: &str,
        request: &MetadataRaftSyncRequest,
    ) -> Result<MetadataRaftSyncResponse, String> {
        let response = client
            .post(url)
            .header("x-rustio-internal-token", internal_token)
            .json(request)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("sync status: {status}, body: {}", body.trim()));
        }
        response
            .json::<MetadataRaftSyncResponse>()
            .await
            .map_err(|err| format!("decode sync response failed: {err}"))
    }

    pub(crate) async fn send_metadata_raft_pre_vote_request(
        client: &Client,
        url: &str,
        internal_token: &str,
        request: &MetadataRaftPreVoteRequest,
    ) -> Result<MetadataRaftPreVoteResponse, String> {
        let response = client
            .post(url)
            .header("x-rustio-internal-token", internal_token)
            .json(request)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("pre-vote status: {}", response.status()));
        }
        response
            .json::<MetadataRaftPreVoteResponse>()
            .await
            .map_err(|err| format!("decode pre-vote response failed: {err}"))
    }

    pub(crate) async fn send_metadata_raft_read_index_request(
        client: &Client,
        url: &str,
        internal_token: &str,
        request: &MetadataRaftReadIndexRequest,
    ) -> Result<MetadataRaftReadIndexResponse, String> {
        let response = client
            .post(url)
            .header("x-rustio-internal-token", internal_token)
            .json(request)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("read-index status: {}", response.status()));
        }
        response
            .json::<MetadataRaftReadIndexResponse>()
            .await
            .map_err(|err| format!("decode read-index response failed: {err}"))
    }

    pub(crate) async fn send_metadata_raft_heartbeat_request(
        client: &Client,
        url: &str,
        internal_token: &str,
        request: &MetadataRaftHeartbeatRequest,
    ) -> Result<MetadataRaftHeartbeatResponse, String> {
        let response = client
            .post(url)
            .header("x-rustio-internal-token", internal_token)
            .json(request)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("heartbeat status: {}", response.status()));
        }
        response
            .json::<MetadataRaftHeartbeatResponse>()
            .await
            .map_err(|err| format!("decode heartbeat response failed: {err}"))
    }

    pub(crate) fn persist_metadata_log_to_peer(
        peer_path: &Path,
        entry: &MetadataRaftLogEntry,
        snapshot_bytes: &[u8],
    ) -> Result<(), String> {
        std::fs::create_dir_all(peer_path).map_err(|err| err.to_string())?;
        let wal_path = peer_path.join("wal.jsonl");
        let line = format!(
            "{}\n",
            serde_json::to_string(entry).map_err(|err| err.to_string())?
        );
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(|err| err.to_string())?;

        let snapshot_path = peer_path.join("snapshot.json");
        std::fs::write(&snapshot_path, snapshot_bytes).map_err(|err| err.to_string())?;

        let snapshots_dir = peer_path.join("snapshots");
        std::fs::create_dir_all(&snapshots_dir).map_err(|err| err.to_string())?;
        let index_snapshot = snapshots_dir.join(format!("{}.json", entry.index));
        std::fs::write(index_snapshot, snapshot_bytes).map_err(|err| err.to_string())?;
        let retain_entries = Self::metadata_wal_retain_entries();
        let _ = Self::compact_metadata_wal_for_peer(peer_path, retain_entries);
        Ok(())
    }

    pub(crate) fn compact_metadata_wal_for_peer(
        peer_path: &Path,
        retain_entries: usize,
    ) -> Result<(), String> {
        let wal_path = peer_path.join("wal.jsonl");
        let content = match std::fs::read_to_string(&wal_path) {
            Ok(value) => value,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.to_string()),
        };
        let mut entries = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_str::<MetadataRaftLogEntry>(line).map_err(|err| err.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if entries.len() <= retain_entries {
            return Ok(());
        }
        entries.sort_by_key(|left| left.index);
        let keep_from = entries.len().saturating_sub(retain_entries);
        let kept_entries = entries.split_off(keep_from);
        let min_kept_index = kept_entries.first().map(|entry| entry.index).unwrap_or(0);
        let wal_bytes = kept_entries
            .iter()
            .map(|item| serde_json::to_string(item).map(|line| format!("{line}\n")))
            .collect::<Result<Vec<_>, _>>()
            .map(|lines| lines.concat())
            .map_err(|err| err.to_string())?;
        let temp_wal = wal_path.with_extension("jsonl.tmp");
        std::fs::write(&temp_wal, wal_bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_wal, &wal_path).map_err(|err| err.to_string())?;

        let snapshots_dir = peer_path.join("snapshots");
        if !snapshots_dir.exists() {
            return Ok(());
        }
        for item in std::fs::read_dir(&snapshots_dir).map_err(|err| err.to_string())? {
            let entry = match item {
                Ok(value) => value,
                Err(_) => continue,
            };
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if !file_name.ends_with(".json") {
                continue;
            }
            let Some(stem) = file_name.strip_suffix(".json") else {
                continue;
            };
            let Ok(index) = stem.parse::<u64>() else {
                continue;
            };
            if index < min_kept_index {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(())
    }

    pub(crate) fn metadata_log_term_from_peer(peer_path: &Path, index: u64, fallback: u64) -> u64 {
        if index == 0 {
            return 0;
        }
        let wal_path = peer_path.join("wal.jsonl");
        let Ok(content) = std::fs::read_to_string(wal_path) else {
            return fallback;
        };
        let mut term = None::<u64>;
        for line in content.lines() {
            if let Ok(entry) = serde_json::from_str::<MetadataRaftLogEntry>(line) {
                if entry.index == index {
                    term = Some(entry.term);
                }
            }
        }
        term.unwrap_or(fallback)
    }

    pub(crate) fn sorted_map_entries<T: Clone>(map: &HashMap<String, T>) -> Vec<(String, T)> {
        let mut entries = map
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    pub(crate) async fn build_metadata_snapshot(&self) -> MetadataRaftSnapshot {
        let mut buckets = self
            .buckets
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        buckets.sort_by(|left, right| left.name.cmp(&right.name));
        let remote_tiers = Self::sorted_map_entries(&self.remote_tiers.read().await.clone());
        let bucket_object_locks =
            Self::sorted_map_entries(&self.bucket_object_locks.read().await.clone());
        let bucket_retentions =
            Self::sorted_map_entries(&self.bucket_retentions.read().await.clone());
        let bucket_legal_holds =
            Self::sorted_map_entries(&self.bucket_legal_holds.read().await.clone());
        let bucket_notifications =
            Self::sorted_map_entries(&self.bucket_notifications.read().await.clone());
        let bucket_lifecycle_rules =
            Self::sorted_map_entries(&self.bucket_lifecycle_rules.read().await.clone());
        let bucket_acls = Self::sorted_map_entries(&self.bucket_acls.read().await.clone());
        let bucket_public_access_blocks =
            Self::sorted_map_entries(&self.bucket_public_access_blocks.read().await.clone());
        let bucket_policies = Self::sorted_map_entries(&self.bucket_policies.read().await.clone());
        let bucket_cors_rules =
            Self::sorted_map_entries(&self.bucket_cors_rules.read().await.clone());
        let bucket_tags = Self::sorted_map_entries(&self.bucket_tags.read().await.clone());
        let bucket_encryptions =
            Self::sorted_map_entries(&self.bucket_encryptions.read().await.clone());

        let mut objects = self
            .object_meta
            .iter()
            .map(|entry| {
                let (bucket, key) = entry.key();
                let meta = entry.value();
                MetadataObjectEntry {
                    bucket: bucket.clone(),
                    key: key.clone(),
                    meta: meta.clone(),
                }
            })
            .collect::<Vec<_>>();
        objects.sort_by(|left, right| {
            left.bucket
                .cmp(&right.bucket)
                .then_with(|| left.key.cmp(&right.key))
        });

        let mut iam_users = self.users.read().await.clone();
        iam_users.sort_by(|left, right| left.username.cmp(&right.username));
        let credentials = Self::sorted_map_entries(&self.credentials.read().await.clone());
        let mut iam_groups = self.groups.read().await.clone();
        iam_groups.sort_by(|left, right| left.name.cmp(&right.name));
        let mut iam_policies = self.policies.read().await.clone();
        iam_policies.sort_by(|left, right| left.name.cmp(&right.name));
        let mut service_accounts = self.service_accounts.read().await.clone();
        service_accounts.sort_by(|left, right| left.access_key.cmp(&right.access_key));
        let mut admin_sessions = self.admin_sessions.read().await.clone();
        admin_sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        let mut sts_sessions = self.sts_sessions.read().await.clone();
        sts_sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        let mut replications = self.replications.read().await.clone();
        replications.sort_by(|left, right| {
            left.source_bucket
                .cmp(&right.source_bucket)
                .then_with(|| left.target_site.cmp(&right.target_site))
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });
        let mut site_replications = self.site_replications.read().await.clone();
        site_replications.sort_by(|left, right| left.site_id.cmp(&right.site_id));
        let mut replication_backlog = self.replication_backlog.read().await.clone();
        replication_backlog.sort_by(|left, right| left.id.cmp(&right.id));
        let replication_checkpoints =
            Self::sorted_map_entries(&self.replication_checkpoints.read().await.clone());
        let cluster_config_history = self.cluster_config_history.read().await.clone();
        let security = self.security.read().await.clone();
        let mut jobs = self.jobs.read().await.clone();
        jobs.sort_by(|left, right| left.id.cmp(&right.id));

        MetadataRaftSnapshot {
            generated_at: Utc::now(),
            buckets,
            remote_tiers,
            bucket_object_locks,
            bucket_retentions,
            bucket_legal_holds,
            bucket_notifications,
            bucket_lifecycle_rules,
            bucket_acls,
            bucket_public_access_blocks,
            bucket_policies,
            bucket_cors_rules,
            bucket_tags,
            bucket_encryptions,
            objects,
            credentials,
            iam_users,
            iam_groups,
            iam_policies,
            service_accounts,
            admin_sessions,
            sts_sessions,
            replications,
            site_replications,
            replication_backlog,
            replication_checkpoints,
            cluster_config_history,
            security,
            jobs,
        }
    }

    pub async fn export_metadata_raft_sync_request(
        &self,
        reason: &str,
    ) -> Result<MetadataRaftSyncRequest, String> {
        let snapshot = self.build_metadata_snapshot().await;
        let raft = self.metadata_raft.read().await;
        let snapshot_hash = if raft.last_snapshot_hash.is_empty() {
            Self::metadata_snapshot_hash(&snapshot)?
        } else {
            raft.last_snapshot_hash.clone()
        };
        let last_commit_term = Self::raft_last_commit_term(&raft);
        let entry = MetadataRaftLogEntry {
            index: raft.commit_index,
            term: if raft.commit_index > 0 {
                last_commit_term
            } else {
                raft.term
            },
            reason: reason.to_string(),
            written_at: raft.last_commit_at.unwrap_or_else(Utc::now),
            snapshot_hash,
        };
        Ok(MetadataRaftSyncRequest {
            cluster_id: raft.cluster_id.clone(),
            peer_id: Self::metadata_local_peer_id(),
            entry,
            prev_log_index: 0,
            prev_log_term: 0,
            install_snapshot: true,
            leader_commit: raft.commit_index,
            snapshot,
        })
    }

    pub(crate) fn replication_state_path(&self) -> PathBuf {
        self.replication_root_dir().join("runtime-state.json")
    }

    pub(crate) fn restore_replication_runtime_state(&self) {
        let state_path = self.replication_state_path();
        let bytes = match std::fs::read(&state_path) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let runtime = match serde_json::from_slice::<ReplicationRuntimeState>(&bytes) {
            Ok(value) => value,
            Err(_) => return,
        };
        if let Ok(mut backlog) = self.replication_backlog.try_write() {
            *backlog = runtime.backlog;
        }
        if let Ok(mut checkpoints) = self.replication_checkpoints.try_write() {
            *checkpoints = runtime.checkpoints;
        }
        let mut next_sequence = runtime.sequence.max(1);
        if let Ok(backlog) = self.replication_backlog.try_read() {
            for item in backlog.iter() {
                next_sequence = next_sequence.max(item.checkpoint.saturating_add(1));
            }
        }
        if let Ok(checkpoints) = self.replication_checkpoints.try_read() {
            for checkpoint in checkpoints.values() {
                next_sequence = next_sequence.max(checkpoint.saturating_add(1));
            }
        }
        self.replication_sequence
            .store(next_sequence.max(1), Ordering::SeqCst);
    }

    pub async fn persist_replication_runtime_state(&self) {
        let runtime = ReplicationRuntimeState {
            version: 1,
            sequence: self.replication_sequence.load(Ordering::SeqCst),
            backlog: self.replication_backlog.read().await.clone(),
            checkpoints: self.replication_checkpoints.read().await.clone(),
        };
        let path = self.replication_state_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(&runtime) {
            let temp_path = path.with_extension("tmp");
            if std::fs::write(&temp_path, bytes).is_ok() {
                let _ = std::fs::rename(temp_path, path);
            }
        }
    }
}
