//! 元数据 Raft 共识：同步、选举、成员变更、请求处理

use super::*;

impl AppState {
    pub async fn sync_metadata_raft(&self, reason: &str) -> Result<(), String> {
        let network_enabled = Self::metadata_network_enabled();
        let local_peer_id = Self::metadata_local_peer_id();
        let force_sync = reason.contains("joint") || reason.starts_with("peer-");
        if network_enabled {
            let raft = self.metadata_raft.read().await;
            if !Self::local_peer_in_membership(&raft, &local_peer_id) {
                return Err(bilingual_runtime_error(
                    "当前节点不在元数据 Raft 成员集合中",
                    "local peer is not in metadata raft membership",
                ));
            }
            if raft.leader_id != local_peer_id {
                return Err(bilingual_runtime_error(
                    "仅 Raft leader 可提交元数据",
                    format!(
                        "metadata raft write must be issued on leader {}, local peer is {}",
                        raft.leader_id, local_peer_id
                    ),
                ));
            }
        }

        let snapshot = self.build_metadata_snapshot().await;
        let snapshot_hash = Self::metadata_snapshot_hash(&snapshot)?;
        let snapshot_bytes = serde_json::to_vec_pretty(&snapshot).map_err(|err| err.to_string())?;
        let now = Utc::now();

        let mut raft = self.metadata_raft.write().await;
        if snapshot_hash == raft.last_snapshot_hash && !force_sync {
            return Ok(());
        }

        let next_index = raft.commit_index + 1;
        let entry = MetadataRaftLogEntry {
            index: next_index,
            term: raft.term,
            reason: reason.to_string(),
            written_at: now,
            snapshot_hash: snapshot_hash.clone(),
        };

        let quorum = Self::metadata_membership_quorum(raft.peers.len());
        let mut last_error = None::<String>;
        let mut max_term_seen = raft.term;
        let network_strict = network_enabled && Self::metadata_network_strict_enabled();
        let internal_token = Self::internal_control_token();
        let cluster_id = raft.cluster_id.clone();
        let local_last_term = Self::raft_last_commit_term(&raft);
        let local_peer_path = raft
            .peers
            .iter()
            .find(|peer| peer.id == local_peer_id)
            .map(|peer| peer.path.clone());
        let http_client = if network_enabled {
            Some(
                Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .map_err(|err| err.to_string())?,
            )
        } else {
            None
        };
        for peer in raft.peers.iter_mut() {
            if !peer.online {
                continue;
            }
            let mut replicated = false;
            if peer.id == local_peer_id {
                match Self::persist_metadata_log_to_peer(&peer.path, &entry, &snapshot_bytes) {
                    Ok(_) => {
                        replicated = true;
                    }
                    Err(err) => {
                        last_error = Some(bilingual_runtime_error(
                            "元数据 Raft 本地节点写入失败",
                            format!("peer {} write failed: {err}", peer.id),
                        ));
                    }
                }
            }
            if replicated {
                peer.last_index = next_index;
                peer.match_index = next_index;
                peer.next_index = next_index.saturating_add(1);
                continue;
            }
            let endpoint = peer
                .endpoint
                .as_ref()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);
            if network_enabled && network_strict && endpoint.is_none() {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 网络同步配置缺失",
                    format!("peer {} missing endpoint in strict mode", peer.id),
                ));
                continue;
            }
            if let (Some(client), Some(endpoint)) = (http_client.as_ref(), endpoint.as_ref()) {
                if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 网络同步配置错误",
                        format!("peer {} endpoint is invalid", peer.id),
                    ));
                    if network_strict {
                        continue;
                    }
                }
                let endpoint = endpoint.trim_end_matches('/');
                let url = format!("{endpoint}/api/v1/internal/metadata-raft/sync");
                let local_path = local_peer_path.as_ref();
                let mut probe_prev_index = peer
                    .next_index
                    .saturating_sub(1)
                    .min(next_index.saturating_sub(1))
                    .max(peer.match_index.min(next_index.saturating_sub(1)));
                let mut append_success = false;
                for _ in 0..5 {
                    let prev_log_term = if let Some(path) = local_path {
                        Self::metadata_log_term_from_peer(path, probe_prev_index, local_last_term)
                    } else if probe_prev_index == 0 {
                        0
                    } else {
                        local_last_term
                    };
                    let request = MetadataRaftSyncRequest {
                        cluster_id: cluster_id.clone(),
                        peer_id: peer.id.clone(),
                        entry: entry.clone(),
                        prev_log_index: probe_prev_index,
                        prev_log_term,
                        install_snapshot: false,
                        leader_commit: next_index,
                        snapshot: snapshot.clone(),
                    };
                    match Self::send_metadata_raft_sync_request(
                        client,
                        &url,
                        &internal_token,
                        &request,
                    )
                    .await
                    {
                        Ok(payload) if payload.success => {
                            max_term_seen = max_term_seen.max(payload.term);
                            peer.match_index = peer.match_index.max(payload.match_index);
                            peer.last_index = peer.last_index.max(peer.match_index);
                            peer.next_index = peer.match_index.saturating_add(1);
                            replicated = true;
                            append_success = true;
                            break;
                        }
                        Ok(payload) => {
                            max_term_seen = max_term_seen.max(payload.term);
                            let reason = payload
                                .reason
                                .unwrap_or_else(|| "append rejected".to_string());
                            if payload.term > entry.term {
                                last_error = Some(bilingual_runtime_error(
                                    "元数据 Raft 网络同步失败",
                                    format!("peer {} has higher term {}", peer.id, payload.term),
                                ));
                                break;
                            }
                            let next_probe = if payload.match_index < probe_prev_index {
                                payload.match_index
                            } else {
                                probe_prev_index.saturating_sub(1)
                            };
                            peer.next_index = next_probe.saturating_add(1);
                            if next_probe == probe_prev_index {
                                last_error = Some(bilingual_runtime_error(
                                    "元数据 Raft 网络同步失败",
                                    format!("peer {} rejected append: {reason}", peer.id),
                                ));
                                break;
                            }
                            probe_prev_index = next_probe;
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 网络同步重试中",
                                format!(
                                    "peer {} append retry with prev_log_index {}: {}",
                                    peer.id, probe_prev_index, reason
                                ),
                            ));
                        }
                        Err(err) => {
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 网络同步失败",
                                format!("peer {} sync request failed: {err}", peer.id),
                            ));
                            break;
                        }
                    }
                }

                if !append_success {
                    let install_snapshot_request = MetadataRaftSyncRequest {
                        cluster_id: cluster_id.clone(),
                        peer_id: peer.id.clone(),
                        entry: entry.clone(),
                        prev_log_index: 0,
                        prev_log_term: 0,
                        install_snapshot: true,
                        leader_commit: next_index,
                        snapshot: snapshot.clone(),
                    };
                    match Self::send_metadata_raft_sync_request(
                        client,
                        &url,
                        &internal_token,
                        &install_snapshot_request,
                    )
                    .await
                    {
                        Ok(payload) if payload.success => {
                            max_term_seen = max_term_seen.max(payload.term);
                            peer.match_index = peer.match_index.max(payload.match_index);
                            peer.last_index = peer.last_index.max(peer.match_index);
                            peer.next_index = peer.match_index.saturating_add(1);
                            replicated = true;
                        }
                        Ok(payload) => {
                            max_term_seen = max_term_seen.max(payload.term);
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 网络同步失败",
                                format!(
                                    "peer {} install-snapshot rejected: {}",
                                    peer.id,
                                    payload
                                        .reason
                                        .unwrap_or_else(|| "snapshot rejected".to_string())
                                ),
                            ));
                        }
                        Err(err) => {
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 网络同步失败",
                                format!("peer {} snapshot sync request failed: {err}", peer.id),
                            ));
                        }
                    }
                }
            }
            if !replicated && network_strict && network_enabled && endpoint.is_some() {
                continue;
            }
            if !replicated {
                match Self::persist_metadata_log_to_peer(&peer.path, &entry, &snapshot_bytes) {
                    Ok(_) => {
                        replicated = true;
                    }
                    Err(err) => {
                        last_error = Some(bilingual_runtime_error(
                            "元数据 Raft 节点写入失败",
                            format!("peer {} write failed: {err}", peer.id),
                        ));
                    }
                }
            }
            if replicated {
                peer.last_index = peer.last_index.max(next_index);
                peer.match_index = peer.match_index.max(peer.last_index);
                peer.next_index = peer.match_index.saturating_add(1);
            }
        }
        raft.term = raft.term.max(max_term_seen);
        if max_term_seen > entry.term {
            raft.voted_for = None;
            if raft.leader_id == local_peer_id {
                raft.leader_id.clear();
            }
            raft.last_error = Some(bilingual_runtime_error(
                "元数据 Raft leader 任期已过期",
                format!(
                    "leader term {} is stale, observed higher term {}",
                    entry.term, max_term_seen
                ),
            ));
            let error_message = raft.last_error.clone().unwrap_or_else(|| {
                bilingual_runtime_error("元数据 Raft 提交失败", "raft leader term is stale")
            });
            let raft_snapshot = raft.clone();
            drop(raft);
            let _ = self.persist_metadata_raft_state_inner(&raft_snapshot);
            return Err(error_message);
        }

        let (quorum_commit_index, quorum_error) = if let Some((old_members, new_members)) =
            Self::effective_joint_members(&raft)
        {
            let old_quorum = Self::metadata_membership_quorum(old_members.len());
            let new_quorum = Self::metadata_membership_quorum(new_members.len());
            let old_online = Self::online_member_count(&raft, &old_members);
            let new_online = Self::online_member_count(&raft, &new_members);
            let old_commit_index = Self::quorum_commit_index_for_members(&raft, &old_members);
            let new_commit_index = Self::quorum_commit_index_for_members(&raft, &new_members);
            let joint_commit_index = old_commit_index.min(new_commit_index);
            if old_online < old_quorum
                || new_online < new_quorum
                || old_commit_index < next_index
                || new_commit_index < next_index
            {
                (
                        joint_commit_index,
                        Some(bilingual_runtime_error(
                            "元数据 Raft joint-consensus 未达到法定票数",
                            format!(
                                "joint quorum not reached: old {old_online}/{old_quorum} commit={old_commit_index}, new {new_online}/{new_quorum} commit={new_commit_index}, expected={next_index}"
                            ),
                        )),
                    )
            } else {
                (joint_commit_index, None)
            }
        } else {
            let mut online_match_indexes = raft
                .peers
                .iter()
                .filter(|peer| peer.online)
                .map(|peer| peer.match_index)
                .collect::<Vec<_>>();
            online_match_indexes.sort_unstable_by(|left, right| right.cmp(left));
            let stable_commit_index = online_match_indexes
                .get(quorum.saturating_sub(1))
                .copied()
                .unwrap_or(0);
            let replicated_peers = raft
                .peers
                .iter()
                .filter(|peer| peer.online && peer.match_index >= next_index)
                .count();
            if stable_commit_index < next_index {
                (
                        stable_commit_index,
                        Some(bilingual_runtime_error(
                            "元数据 Raft 未达到法定票数",
                            format!(
                                "raft quorum not reached: replicated peers {replicated_peers}/{quorum}, quorum_commit_index={stable_commit_index}, expected={next_index}"
                            ),
                        )),
                    )
            } else {
                (stable_commit_index, None)
            }
        };

        if let Some(quorum_error) = quorum_error {
            raft.last_error = Some(last_error.unwrap_or(quorum_error));
            let error_message = raft.last_error.clone().unwrap_or_else(|| {
                bilingual_runtime_error("元数据 Raft 提交失败", "raft commit failed")
            });
            let raft_snapshot = raft.clone();
            drop(raft);
            let _ = self.persist_metadata_raft_state_inner(&raft_snapshot);
            return Err(error_message);
        }

        raft.commit_index = raft.commit_index.max(quorum_commit_index);
        if raft.commit_index >= next_index {
            raft.last_commit_term = entry.term;
        }
        raft.last_snapshot_hash = snapshot_hash;
        raft.last_commit_at = Some(now);
        raft.last_quorum_at = Some(now);
        raft.last_error = None;
        let raft_snapshot = raft.clone();
        drop(raft);
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        Ok(())
    }

    pub(crate) async fn restore_metadata_raft_on_startup(&self) -> Result<(), String> {
        self.restore_metadata_raft_from_local_snapshot().await?;
        if !Self::metadata_network_enabled() {
            return Ok(());
        }

        let mut last_error = None::<String>;
        for _ in 0..8 {
            match self.catchup_metadata_raft_from_remote_peers().await {
                Ok(_) => return Ok(()),
                Err(err) => {
                    last_error = Some(err);
                    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                }
            }
        }
        if let Some(err) = last_error {
            return Err(err);
        }
        Ok(())
    }

    pub(crate) async fn restore_metadata_raft_from_local_snapshot(&self) -> Result<(), String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let peer_root = self.data_dir.join(".rustio_meta_raft").join(&local_peer_id);
        let wal_entries = std::fs::read_to_string(peer_root.join("wal.jsonl"))
            .ok()
            .map(|content| {
                content
                    .lines()
                    .filter_map(|line| serde_json::from_str::<MetadataRaftLogEntry>(line).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut wal_entries = wal_entries;
        wal_entries.sort_by_key(|left| left.index);

        let cluster_id = self.metadata_raft.read().await.cluster_id.clone();
        let mut applied = false;
        let snapshots_dir = peer_root.join("snapshots");

        for entry in wal_entries.iter() {
            let candidate_path = snapshots_dir.join(format!("{}.json", entry.index));
            if !candidate_path.exists() {
                continue;
            }
            let snapshot_bytes = match std::fs::read(&candidate_path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let snapshot = match serde_json::from_slice::<MetadataRaftSnapshot>(&snapshot_bytes) {
                Ok(snapshot) => snapshot,
                Err(_) => continue,
            };
            let mut entry = entry.clone();
            if entry.snapshot_hash.is_empty() {
                entry.snapshot_hash = Self::metadata_snapshot_hash(&snapshot)?;
            }
            let leader_commit = entry.index;
            let request = MetadataRaftSyncRequest {
                cluster_id: cluster_id.clone(),
                peer_id: local_peer_id.clone(),
                entry,
                prev_log_index: 0,
                prev_log_term: 0,
                install_snapshot: true,
                leader_commit,
                snapshot,
            };
            let response = self
                .apply_metadata_raft_snapshot_internal(request, false)
                .await?;
            if !response.success {
                return Err(bilingual_runtime_error(
                    "本地元数据 Raft 重放失败",
                    response
                        .reason
                        .unwrap_or_else(|| "local metadata raft replay rejected".to_string()),
                ));
            }
            applied = true;
        }

        if applied {
            return Ok(());
        }

        let snapshot_path = peer_root.join("snapshot.json");
        if !snapshot_path.exists() {
            return Ok(());
        }
        let snapshot_bytes = std::fs::read(&snapshot_path).map_err(|err| {
            bilingual_runtime_error(
                "读取元数据快照失败",
                format!("failed to read metadata raft snapshot: {err}"),
            )
        })?;
        let snapshot =
            serde_json::from_slice::<MetadataRaftSnapshot>(&snapshot_bytes).map_err(|err| {
                bilingual_runtime_error(
                    "解析元数据快照失败",
                    format!("failed to decode metadata raft snapshot: {err}"),
                )
            })?;
        let mut entry = wal_entries.last().cloned().unwrap_or(MetadataRaftLogEntry {
            index: 0,
            term: 1,
            reason: "startup-restore".to_string(),
            written_at: Utc::now(),
            snapshot_hash: String::new(),
        });
        if entry.snapshot_hash.is_empty() {
            entry.snapshot_hash = Self::metadata_snapshot_hash(&snapshot)?;
        }
        let leader_commit = entry.index;
        let request = MetadataRaftSyncRequest {
            cluster_id,
            peer_id: local_peer_id,
            entry,
            prev_log_index: 0,
            prev_log_term: 0,
            install_snapshot: true,
            leader_commit,
            snapshot,
        };
        let response = self
            .apply_metadata_raft_snapshot_internal(request, false)
            .await?;
        if response.success {
            Ok(())
        } else {
            Err(bilingual_runtime_error(
                "本地元数据 Raft 恢复失败",
                response
                    .reason
                    .unwrap_or_else(|| "local metadata raft restore rejected".to_string()),
            ))
        }
    }

    pub(crate) async fn catchup_metadata_raft_from_remote_peers(&self) -> Result<(), String> {
        if !Self::metadata_network_enabled() {
            return Ok(());
        }

        let endpoints = Self::metadata_peer_endpoints();
        let local_peer_id = Self::metadata_local_peer_id();
        let internal_token = Self::internal_control_token();
        let current_index = self.metadata_raft.read().await.commit_index;
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|err| err.to_string())?;

        let mut best_remote = None::<MetadataRaftSyncRequest>;
        let mut last_error = None::<String>;
        let mut attempted = 0usize;

        for (peer_id, endpoint_raw) in endpoints {
            if peer_id == local_peer_id {
                continue;
            }
            let endpoint = endpoint_raw.trim().trim_end_matches('/');
            if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
                continue;
            }
            attempted += 1;
            let url = format!("{endpoint}/api/v1/internal/metadata-raft/export");
            match client
                .get(url)
                .header("x-rustio-internal-token", &internal_token)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    match response.json::<MetadataRaftSyncRequest>().await {
                        Ok(mut payload) => {
                            payload.peer_id = local_peer_id.clone();
                            payload.install_snapshot = true;
                            payload.prev_log_index = 0;
                            payload.prev_log_term = 0;
                            if payload.leader_commit == 0 {
                                payload.leader_commit = payload.entry.index;
                            }
                            if payload.entry.index <= current_index {
                                continue;
                            }
                            let replace = best_remote
                                .as_ref()
                                .map(|item| payload.entry.index > item.entry.index)
                                .unwrap_or(true);
                            if replace {
                                best_remote = Some(payload);
                            }
                        }
                        Err(err) => {
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 追平失败",
                                format!("decode remote raft snapshot failed: {err}"),
                            ));
                        }
                    }
                }
                Ok(response) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 追平失败",
                        format!("remote raft export status: {}", response.status()),
                    ));
                }
                Err(err) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 追平失败",
                        format!("remote raft export request failed: {err}"),
                    ));
                }
            }
        }

        if let Some(request) = best_remote {
            let response = self
                .apply_metadata_raft_snapshot_internal(request, true)
                .await?;
            if response.success {
                return Ok(());
            }
            return Err(bilingual_runtime_error(
                "元数据 Raft 追平被拒绝",
                response
                    .reason
                    .unwrap_or_else(|| "metadata raft catch-up rejected".to_string()),
            ));
        }

        if attempted == 0 {
            return Ok(());
        }
        if let Some(err) = last_error {
            return Err(err);
        }
        Ok(())
    }

    pub(crate) async fn process_metadata_raft_heartbeat_once(&self) -> Result<(), String> {
        if !Self::metadata_network_enabled() {
            return Ok(());
        }

        let local_peer_id = Self::metadata_local_peer_id();
        let (
            cluster_id,
            leader_id,
            term,
            commit_index,
            peers,
            last_heartbeat_at,
            last_election_at,
            last_quorum_at,
            local_online,
        ) = {
            let raft = self.metadata_raft.read().await;
            (
                raft.cluster_id.clone(),
                raft.leader_id.clone(),
                raft.term,
                raft.commit_index,
                raft.peers.clone(),
                raft.last_heartbeat_at,
                raft.last_election_at,
                raft.last_quorum_at,
                raft.peers
                    .iter()
                    .any(|peer| peer.id == local_peer_id && peer.online),
            )
        };

        if !local_online {
            return Ok(());
        }

        if leader_id == local_peer_id {
            let internal_token = Self::internal_control_token();
            let client = Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()
                .map_err(|err| err.to_string())?;
            let request = MetadataRaftHeartbeatRequest {
                cluster_id,
                leader_id: local_peer_id.clone(),
                term,
                leader_commit: commit_index,
            };

            let quorum = peers.len() / 2 + 1;
            let mut heartbeat_acks = 1usize;
            let mut max_term_seen = term;
            let mut last_error = None::<String>;
            for peer in peers {
                if !peer.online || peer.id == local_peer_id {
                    continue;
                }
                let Some(endpoint) = peer
                    .endpoint
                    .as_ref()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                else {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 心跳失败",
                        format!("peer {} missing endpoint", peer.id),
                    ));
                    continue;
                };
                if !Self::metadata_peer_endpoint_valid(&endpoint) {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 心跳失败",
                        format!("peer {} endpoint is invalid", peer.id),
                    ));
                    continue;
                }
                let url = format!(
                    "{}/api/v1/internal/metadata-raft/heartbeat",
                    endpoint.trim_end_matches('/')
                );
                match Self::send_metadata_raft_heartbeat_request(
                    &client,
                    &url,
                    &internal_token,
                    &request,
                )
                .await
                {
                    Ok(payload) => {
                        max_term_seen = max_term_seen.max(payload.term);
                        if payload.accepted {
                            heartbeat_acks += 1;
                        } else {
                            let reason = payload
                                .reason
                                .unwrap_or_else(|| "heartbeat rejected".to_string());
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 心跳失败",
                                format!("peer {} rejected heartbeat: {reason}", peer.id),
                            ));
                        }
                    }
                    Err(err) => {
                        last_error = Some(bilingual_runtime_error(
                            "元数据 Raft 心跳失败",
                            format!("peer {} heartbeat request failed: {err}", peer.id),
                        ));
                    }
                }
            }

            let mut raft = self.metadata_raft.write().await;
            if max_term_seen > raft.term {
                raft.term = max_term_seen;
                raft.voted_for = None;
                if raft.leader_id == local_peer_id {
                    raft.leader_id.clear();
                }
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft leader 任期已过期",
                    format!(
                        "leader term {} is stale, observed higher term {}",
                        term, max_term_seen
                    ),
                ));
            } else {
                let now = Utc::now();
                let previous_quorum_at = raft.last_quorum_at.or(last_quorum_at).unwrap_or(now);
                raft.last_heartbeat_at = Some(now);
                if heartbeat_acks >= quorum {
                    raft.last_quorum_at = Some(now);
                    raft.last_error = None;
                } else {
                    let quorum_lost_for = now
                        .signed_duration_since(previous_quorum_at)
                        .to_std()
                        .unwrap_or_default();
                    if quorum_lost_for >= Self::metadata_election_timeout() {
                        if raft.leader_id == local_peer_id {
                            raft.leader_id.clear();
                            raft.voted_for = None;
                        }
                        raft.last_election_at = Some(now);
                        raft.last_error = Some(bilingual_runtime_error(
                            "元数据 Raft leader 丢失法定票数",
                            format!(
                                "metadata raft leader lost quorum: heartbeat acknowledgements {heartbeat_acks}/{quorum}"
                            ),
                        ));
                    } else {
                        raft.last_error = Some(last_error.unwrap_or_else(|| {
                            bilingual_runtime_error(
                                "元数据 Raft 心跳未达到法定票数",
                                format!(
                                    "heartbeat acknowledgements below quorum: {heartbeat_acks}/{quorum}"
                                ),
                            )
                        }));
                    }
                }
            }
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Ok(());
        }

        let now = Utc::now();
        let heartbeat_timed_out = last_heartbeat_at
            .and_then(|ts| now.signed_duration_since(ts).to_std().ok())
            .map(|elapsed| elapsed >= Self::metadata_election_timeout())
            .unwrap_or(true);
        let in_cooldown = last_election_at
            .and_then(|ts| now.signed_duration_since(ts).to_std().ok())
            .map(|elapsed| elapsed < Self::metadata_election_cooldown())
            .unwrap_or(false);
        if !heartbeat_timed_out || in_cooldown {
            return Ok(());
        }

        match self.elect_metadata_leader(&local_peer_id).await {
            Ok(_) => Ok(()),
            Err(err) => {
                let mut raft = self.metadata_raft.write().await;
                raft.last_error = Some(err.clone());
                let raft_snapshot = raft.clone();
                drop(raft);
                self.persist_metadata_raft_state_inner(&raft_snapshot)?;
                Err(err)
            }
        }
    }

    pub(crate) fn metadata_joint_elapsed_seconds(
        raft: &MetadataRaftState,
        now: DateTime<Utc>,
    ) -> Option<u64> {
        if raft.membership_phase != "joint" {
            return None;
        }
        let anchor = raft
            .last_commit_at
            .or(raft.last_heartbeat_at)
            .or(raft.last_election_at)?;
        let elapsed = now
            .signed_duration_since(anchor)
            .to_std()
            .unwrap_or_default()
            .as_secs();
        Some(elapsed)
    }

    pub(crate) fn metadata_raft_status_from_state(raft: &MetadataRaftState) -> MetadataRaftStatus {
        let now = Utc::now();
        let quorum = Self::metadata_membership_quorum(raft.peers.len());
        let online_peers = raft.peers.iter().filter(|peer| peer.online).count();
        MetadataRaftStatus {
            cluster_id: raft.cluster_id.clone(),
            leader_id: raft.leader_id.clone(),
            term: raft.term,
            commit_index: raft.commit_index,
            quorum,
            online_peers,
            last_error: raft.last_error.clone(),
            last_commit_at: raft.last_commit_at,
            membership_phase: raft.membership_phase.clone(),
            joint_old_members: Self::canonical_member_ids(raft.joint_old_members.clone()),
            joint_new_members: Self::canonical_member_ids(raft.joint_new_members.clone()),
            joint_elapsed_seconds: Self::metadata_joint_elapsed_seconds(raft, now),
            joint_timeout_seconds: Self::metadata_membership_change_timeout().as_secs(),
            peers: raft.peers.clone(),
        }
    }

    pub(crate) async fn process_metadata_membership_watchdog_once(&self) -> Result<(), String> {
        let now = Utc::now();
        let timeout = Self::metadata_membership_change_timeout();
        let timeout_secs = timeout.as_secs();
        let timeout_prefix = "元数据 Raft 成员变更超时，请执行 finalize 或 abort";
        let (joint_elapsed_secs, timeout_triggered) = {
            let mut raft = self.metadata_raft.write().await;
            let Some(elapsed_secs) = Self::metadata_joint_elapsed_seconds(&raft, now) else {
                if raft
                    .last_error
                    .as_deref()
                    .map(|message| message.contains(timeout_prefix))
                    .unwrap_or(false)
                {
                    raft.last_error = None;
                    let raft_snapshot = raft.clone();
                    drop(raft);
                    self.persist_metadata_raft_state_inner(&raft_snapshot)?;
                }
                return Self::resolve_membership_watchdog_alerts(&self.alert_history, now).await;
            };
            let elapsed = std::time::Duration::from_secs(elapsed_secs);
            if elapsed < timeout {
                (Some(elapsed_secs), false)
            } else {
                let timeout_error = bilingual_runtime_error(
                    timeout_prefix,
                    format!(
                        "metadata raft membership change timed out: joint elapsed {}s exceeds timeout {}s, please finalize or abort",
                        elapsed_secs, timeout_secs
                    ),
                );
                if raft.last_error.as_deref() != Some(timeout_error.as_str()) {
                    raft.last_error = Some(timeout_error);
                    let raft_snapshot = raft.clone();
                    drop(raft);
                    self.persist_metadata_raft_state_inner(&raft_snapshot)?;
                }
                (Some(elapsed_secs), true)
            }
        };
        if !timeout_triggered {
            return Ok(());
        }

        let mut history = self.alert_history.write().await;
        let already_firing = history.iter().any(|entry| {
            entry.source == "metadata-raft-membership-watchdog"
                && entry.status == "firing"
                && entry.resolved_at.is_none()
        });
        if already_firing {
            return Ok(());
        }
        history.push(AlertHistoryEntry {
            id: format!("history-{}", Uuid::new_v4().simple()),
            rule_id: None,
            rule_name: Some("元数据 Raft 成员变更超时".to_string()),
            severity: "warning".to_string(),
            status: "firing".to_string(),
            message: bilingual_runtime_error(
                "元数据 Raft 成员变更长时间处于 joint 阶段",
                "metadata raft membership change is stuck in joint phase",
            ),
            triggered_at: now,
            source: "metadata-raft-membership-watchdog".to_string(),
            assignee: None,
            claimed_at: None,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved_by: None,
            resolved_at: None,
            details: json!({
                "membership_phase": "joint",
                "joint_elapsed_seconds": joint_elapsed_secs,
                "joint_timeout_seconds": timeout_secs,
            }),
        });
        Ok(())
    }

    pub(crate) async fn resolve_membership_watchdog_alerts(
        alert_history: &RwLock<Vec<AlertHistoryEntry>>,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let mut history = alert_history.write().await;
        let mut changed = false;
        for entry in history.iter_mut() {
            if entry.source == "metadata-raft-membership-watchdog"
                && entry.status == "firing"
                && entry.resolved_at.is_none()
            {
                entry.status = "resolved".to_string();
                entry.resolved_by = Some("system".to_string());
                entry.resolved_at = Some(now);
                entry.message = bilingual_runtime_error(
                    "元数据 Raft 成员变更已恢复",
                    "metadata raft membership change recovered",
                );
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        Ok(())
    }

    pub async fn metadata_raft_status(&self) -> MetadataRaftStatus {
        let raft = self.metadata_raft.read().await;
        Self::metadata_raft_status_from_state(&raft)
    }

    pub(crate) fn verify_membership_quorum_available(
        raft: &MetadataRaftState,
    ) -> Result<(), String> {
        if let Some((old_members, new_members)) = Self::effective_joint_members(raft) {
            let old_quorum = Self::metadata_membership_quorum(old_members.len());
            let new_quorum = Self::metadata_membership_quorum(new_members.len());
            let old_online = Self::online_member_count(raft, &old_members);
            let new_online = Self::online_member_count(raft, &new_members);
            if old_online < old_quorum || new_online < new_quorum {
                return Err(format!(
                    "joint quorum unavailable: old {old_online}/{old_quorum}, new {new_online}/{new_quorum}"
                ));
            }
            return Ok(());
        }
        let quorum = Self::metadata_membership_quorum(raft.peers.len());
        let online = raft.peers.iter().filter(|peer| peer.online).count();
        if online < quorum {
            return Err(format!("quorum unavailable: {online}/{quorum}"));
        }
        Ok(())
    }

    pub async fn handle_metadata_read_index_request(
        &self,
        request: MetadataRaftReadIndexRequest,
    ) -> Result<MetadataRaftReadIndexResponse, String> {
        let request_id = request.request_id.trim().to_string();
        if !Self::metadata_read_index_request_id_valid(&request_id) {
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引请求 ID 无效",
                "invalid metadata raft read-index request id",
            ));
        }
        let local_peer_id = Self::metadata_local_peer_id();
        let mut raft = self.metadata_raft.write().await;
        if raft.cluster_id != request.cluster_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 集群标识不匹配",
                format!(
                    "metadata raft cluster mismatch: expected {}, got {}",
                    raft.cluster_id, request.cluster_id
                ),
            ));
        }
        if !Self::local_peer_in_membership(&raft, &local_peer_id) {
            return Ok(MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: false,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: Some("local peer not in membership".to_string()),
            });
        }

        if raft.leader_id != local_peer_id {
            return Ok(MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: false,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: Some("not leader".to_string()),
            });
        }

        if let Err(reason) = Self::verify_membership_quorum_available(&raft) {
            raft.last_error = Some(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                format!("metadata raft read-index quorum unavailable: {reason}"),
            ));
            let response = MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: false,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: Some(reason),
            };
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Ok(response);
        }

        let now = Utc::now();
        let quorum_fresh = raft
            .last_quorum_at
            .and_then(|ts| now.signed_duration_since(ts).to_std().ok())
            .map(|elapsed| elapsed < Self::metadata_election_timeout())
            .unwrap_or(false);
        if !quorum_fresh {
            let reason = "quorum heartbeat is stale".to_string();
            raft.last_error = Some(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                format!("metadata raft read-index rejected: {reason}"),
            ));
            let response = MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: false,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: Some(reason),
            };
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Ok(response);
        }

        raft.last_quorum_at = Some(now);
        raft.last_heartbeat_at = Some(now);
        raft.last_error = None;
        let response = MetadataRaftReadIndexResponse {
            term: raft.term,
            leader_id: raft.leader_id.clone(),
            read_index: raft.commit_index,
            success: true,
            request_id,
            members: Self::canonical_member_ids(
                raft.peers.iter().map(|peer| peer.id.clone()).collect(),
            ),
            reason: None,
        };
        let raft_snapshot = raft.clone();
        drop(raft);
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        Ok(response)
    }

    pub async fn metadata_read_index(&self) -> Result<MetadataRaftReadIndexResponse, String> {
        let request_id = format!("readidx-{}", Uuid::new_v4().simple());
        if !Self::metadata_network_enabled() {
            let raft = self.metadata_raft.read().await;
            return Ok(MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: true,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: None,
            });
        }

        let local_peer_id = Self::metadata_local_peer_id();
        let (cluster_id, leader_id, term, leader_endpoint, probe_targets, local_member) = {
            let raft = self.metadata_raft.read().await;
            let mut targets = Vec::new();
            for peer in raft.peers.iter().filter(|peer| peer.id != local_peer_id) {
                if let Some(endpoint) = Self::metadata_peer_endpoint_from_raft(&raft, &peer.id) {
                    targets.push((peer.id.clone(), endpoint));
                }
            }
            (
                raft.cluster_id.clone(),
                raft.leader_id.clone(),
                raft.term,
                if raft.leader_id == local_peer_id {
                    None
                } else {
                    Self::metadata_peer_endpoint_from_raft(&raft, &raft.leader_id)
                },
                targets,
                raft.peers.iter().any(|peer| peer.id == local_peer_id),
            )
        };

        if !local_member {
            return Err(bilingual_runtime_error(
                "当前节点不在元数据 Raft 成员集合中",
                "local peer is not in metadata raft membership",
            ));
        }

        if leader_id == local_peer_id {
            let payload = self
                .handle_metadata_read_index_request(MetadataRaftReadIndexRequest {
                    cluster_id,
                    requester_id: local_peer_id,
                    request_id,
                })
                .await?;
            if payload.success {
                return Ok(payload);
            }
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                payload
                    .reason
                    .unwrap_or_else(|| "metadata raft read-index rejected".to_string()),
            ));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .map_err(|err| err.to_string())?;
        let request = MetadataRaftReadIndexRequest {
            cluster_id,
            requester_id: local_peer_id.clone(),
            request_id,
        };
        let mut last_probe_error = None::<String>;

        if !leader_id.trim().is_empty() {
            if let Some(endpoint) = leader_endpoint.map(|value| value.trim().to_string()) {
                match self
                    .request_metadata_read_index_from_endpoint(
                        &client, &request, &leader_id, &endpoint, term,
                    )
                    .await
                {
                    Ok(payload) => return Ok(payload),
                    Err(err) => last_probe_error = Some(err),
                }
            } else {
                last_probe_error = Some(bilingual_runtime_error(
                    "元数据 Raft leader endpoint 缺失",
                    format!("metadata raft leader {} endpoint is missing", leader_id),
                ));
            }
        }

        for (peer_id, endpoint) in probe_targets {
            match self
                .request_metadata_read_index_from_endpoint(
                    &client, &request, &peer_id, &endpoint, term,
                )
                .await
            {
                Ok(payload) => return Ok(payload),
                Err(err) => last_probe_error = Some(err),
            }
        }

        Err(bilingual_runtime_error(
            "当前无可用元数据 Raft leader",
            last_probe_error.unwrap_or_else(|| "metadata raft leader unavailable".to_string()),
        ))
    }

    pub(crate) async fn request_metadata_read_index_from_endpoint(
        &self,
        client: &Client,
        request: &MetadataRaftReadIndexRequest,
        leader_id_hint: &str,
        endpoint: &str,
        local_term: u64,
    ) -> Result<MetadataRaftReadIndexResponse, String> {
        if !Self::metadata_peer_endpoint_valid(endpoint) {
            return Err(bilingual_runtime_error(
                "元数据 Raft leader endpoint 无效",
                format!(
                    "metadata raft leader {} endpoint is invalid",
                    leader_id_hint
                ),
            ));
        }
        let url = format!(
            "{}/api/v1/internal/metadata-raft/read-index",
            endpoint.trim_end_matches('/')
        );
        let payload = Self::send_metadata_raft_read_index_request(
            client,
            &url,
            &Self::internal_control_token(),
            request,
        )
        .await
        .map_err(|err| {
            bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                format!("read-index request failed: {err}"),
            )
        })?;
        if !payload.success {
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                payload
                    .reason
                    .clone()
                    .unwrap_or_else(|| "metadata raft read-index rejected".to_string()),
            ));
        }
        if payload.request_id != request.request_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引响应 ID 不匹配",
                format!(
                    "read-index response request id mismatch: expected {}, got {}",
                    request.request_id, payload.request_id
                ),
            ));
        }
        if !payload.members.is_empty()
            && !payload
                .members
                .iter()
                .any(|member_id| member_id == &request.requester_id)
        {
            let _ = self
                .mark_local_peer_removed_from_membership(
                    &payload.leader_id,
                    payload.term,
                    &payload.members,
                )
                .await;
            return Err(bilingual_runtime_error(
                "当前节点不在元数据 Raft 成员集合中",
                format!(
                    "local peer {} is not in leader membership set",
                    request.requester_id
                ),
            ));
        }
        if payload.term < local_term {
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                format!(
                    "read-index leader term is stale: local={}, remote={}",
                    local_term, payload.term
                ),
            ));
        }
        self.catchup_metadata_to_read_index(payload.read_index)
            .await?;
        Ok(payload)
    }

    pub(crate) async fn catchup_metadata_to_read_index(
        &self,
        required_read_index: u64,
    ) -> Result<(), String> {
        let local_commit = self.metadata_raft.read().await.commit_index;
        if local_commit >= required_read_index {
            return Ok(());
        }
        for _ in 0..6 {
            let _ = self.catchup_metadata_raft_from_remote_peers().await;
            let current_commit = self.metadata_raft.read().await.commit_index;
            if current_commit >= required_read_index {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        }
        Err(bilingual_runtime_error(
            "元数据 Raft 读索引追平失败",
            format!(
                "metadata read-index catch-up not reached: local_commit={}, required={}",
                self.metadata_raft.read().await.commit_index,
                required_read_index
            ),
        ))
    }

    pub(crate) async fn mark_local_peer_removed_from_membership(
        &self,
        leader_id: &str,
        leader_term: u64,
        members: &[String],
    ) -> Result<(), String> {
        let local_peer_id = Self::metadata_local_peer_id();
        if members.iter().any(|member| member == &local_peer_id) {
            return Ok(());
        }

        let raft_snapshot = {
            let mut raft = self.metadata_raft.write().await;
            let mut changed = false;
            let original_len = raft.peers.len();
            raft.peers.retain(|peer| peer.id != local_peer_id);
            if raft.peers.len() != original_len {
                changed = true;
            }
            let leader_id = leader_id.trim();
            if !leader_id.is_empty() && raft.leader_id != leader_id {
                raft.leader_id = leader_id.to_string();
                changed = true;
            }
            if leader_term > raft.term {
                raft.term = leader_term;
                raft.voted_for = None;
                changed = true;
            }
            if raft.voted_for.as_deref() == Some(local_peer_id.as_str()) {
                raft.voted_for = None;
                changed = true;
            }
            if raft.membership_phase != "stable" {
                raft.membership_phase = "stable".to_string();
                raft.joint_old_members.clear();
                raft.joint_new_members.clear();
                changed = true;
            }
            let local_removed_error = bilingual_runtime_error(
                "当前节点已被移出元数据 Raft 成员集合",
                "local peer has been removed from metadata raft membership",
            );
            if raft.last_error.as_deref() != Some(local_removed_error.as_str()) {
                raft.last_error = Some(local_removed_error);
                changed = true;
            }
            changed.then(|| raft.clone())
        };
        if let Some(raft_snapshot) = raft_snapshot {
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        }
        Ok(())
    }

    pub(crate) fn metadata_peer_id_valid(peer_id: &str) -> bool {
        !peer_id.is_empty()
            && peer_id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    }

    pub(crate) fn metadata_read_index_request_id_valid(request_id: &str) -> bool {
        !request_id.is_empty()
            && request_id.len() <= 96
            && request_id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    }

    pub(crate) fn metadata_peer_endpoint_valid(endpoint: &str) -> bool {
        let value = endpoint.trim();
        value.starts_with("http://") || value.starts_with("https://")
    }

    pub(crate) fn metadata_peer_endpoint_from_raft(
        raft: &MetadataRaftState,
        peer_id: &str,
    ) -> Option<String> {
        let endpoint_from_state = raft
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .and_then(|peer| peer.endpoint.clone())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if endpoint_from_state.is_some() {
            return endpoint_from_state;
        }
        Self::metadata_peer_endpoints().get(peer_id).cloned()
    }

    pub(crate) fn canonical_member_ids(ids: Vec<String>) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut members = ids
            .into_iter()
            .filter(|id| !id.trim().is_empty())
            .filter(|id| seen.insert(id.clone()))
            .collect::<Vec<_>>();
        members.sort();
        members
    }

    pub(crate) fn local_peer_in_membership(raft: &MetadataRaftState, local_peer_id: &str) -> bool {
        raft.peers.iter().any(|peer| peer.id == local_peer_id)
    }

    pub(crate) fn metadata_membership_quorum(member_count: usize) -> usize {
        member_count / 2 + 1
    }

    pub(crate) fn effective_joint_members(
        raft: &MetadataRaftState,
    ) -> Option<(Vec<String>, Vec<String>)> {
        if raft.membership_phase != "joint" {
            return None;
        }
        let old_members = Self::canonical_member_ids(raft.joint_old_members.clone());
        let new_members = Self::canonical_member_ids(raft.joint_new_members.clone());
        if old_members.is_empty() || new_members.is_empty() {
            return None;
        }
        Some((old_members, new_members))
    }

    pub(crate) fn online_member_count(raft: &MetadataRaftState, members: &[String]) -> usize {
        let member_set = members.iter().collect::<HashSet<_>>();
        raft.peers
            .iter()
            .filter(|peer| peer.online && member_set.contains(&peer.id))
            .count()
    }

    pub(crate) fn quorum_commit_index_for_members(
        raft: &MetadataRaftState,
        members: &[String],
    ) -> u64 {
        let member_set = members.iter().collect::<HashSet<_>>();
        let mut indexes = raft
            .peers
            .iter()
            .filter(|peer| peer.online && member_set.contains(&peer.id))
            .map(|peer| peer.match_index)
            .collect::<Vec<_>>();
        indexes.sort_unstable_by(|left, right| right.cmp(left));
        let quorum = Self::metadata_membership_quorum(members.len());
        indexes.get(quorum.saturating_sub(1)).copied().unwrap_or(0)
    }

    pub(crate) fn elect_metadata_raft_leader_if_needed(raft: &mut MetadataRaftState) {
        let leader_online = raft
            .peers
            .iter()
            .any(|peer| peer.id == raft.leader_id && peer.online);
        if leader_online {
            return;
        }
        let mut candidates = raft
            .peers
            .iter()
            .filter(|peer| peer.online)
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .last_index
                .cmp(&left.last_index)
                .then_with(|| left.id.cmp(&right.id))
        });
        if let Some(candidate) = candidates.first() {
            if raft.leader_id != candidate.id {
                raft.leader_id = candidate.id.clone();
                raft.term = raft.term.saturating_add(1);
                raft.voted_for = None;
            }
        }
    }

    pub async fn set_metadata_peer_state(
        &self,
        peer_id: &str,
        online: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let mut raft = self.metadata_raft.write().await;
        let Some(peer) = raft.peers.iter_mut().find(|item| item.id == peer_id) else {
            return Err(bilingual_runtime_error(
                "未找到元数据 Raft 节点",
                "metadata raft peer not found",
            ));
        };
        peer.online = online;
        Self::elect_metadata_raft_leader_if_needed(&mut raft);
        let status = Self::metadata_raft_status_from_state(&raft);
        let raft_snapshot = raft.clone();
        drop(raft);
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        Ok(status)
    }

    pub async fn abort_metadata_membership_change(&self) -> Result<MetadataRaftStatus, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let network_enabled = Self::metadata_network_enabled();
        let (abort_snapshot, rollback_snapshot) = {
            let mut raft = self.metadata_raft.write().await;
            if raft.membership_phase != "joint" {
                return Err(bilingual_runtime_error(
                    "当前无进行中的元数据 Raft joint-consensus 变更",
                    "no metadata raft joint-consensus change in progress",
                ));
            }
            if !Self::local_peer_in_membership(&raft, &local_peer_id) {
                return Err(bilingual_runtime_error(
                    "当前节点不在元数据 Raft 成员集合中",
                    "local peer is not in metadata raft membership",
                ));
            }
            if network_enabled && raft.leader_id != local_peer_id {
                return Err(bilingual_runtime_error(
                    "仅 Raft leader 可中止成员变更",
                    format!(
                        "metadata raft membership abort must be issued on leader {}, local peer is {}",
                        raft.leader_id, local_peer_id
                    ),
                ));
            }

            let old_members = Self::canonical_member_ids(raft.joint_old_members.clone());
            if old_members.is_empty() {
                return Err(bilingual_runtime_error(
                    "joint-consensus 旧成员集合为空，无法中止",
                    "joint-consensus old membership set is empty and cannot be aborted",
                ));
            }

            let rollback_snapshot = raft.clone();
            let mut merged_peers = old_members
                .iter()
                .map(|member_id| {
                    if let Some(existing) = raft.peers.iter().find(|peer| &peer.id == member_id) {
                        return existing.clone();
                    }
                    let peer_path = Self::metadata_raft_root_dir(&self.data_dir).join(member_id);
                    let _ = std::fs::create_dir_all(&peer_path);
                    MetadataRaftPeer {
                        id: member_id.clone(),
                        path: peer_path,
                        endpoint: Self::metadata_peer_endpoints().get(member_id).cloned(),
                        online: false,
                        match_index: raft.commit_index,
                        next_index: raft.commit_index.saturating_add(1),
                        last_index: raft.commit_index,
                    }
                })
                .collect::<Vec<_>>();
            merged_peers.sort_by(|left, right| left.id.cmp(&right.id));

            raft.peers = merged_peers;
            raft.membership_phase = "stable".to_string();
            raft.joint_old_members.clear();
            raft.joint_new_members.clear();
            Self::elect_metadata_raft_leader_if_needed(&mut raft);
            raft.last_error = None;
            (raft.clone(), rollback_snapshot)
        };
        self.persist_metadata_raft_state_inner(&abort_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-joint-abort").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                *raft = rollback_snapshot.clone();
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 成员变更中止失败",
                    format!("metadata raft membership abort failed: {err}"),
                ));
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            return Err(bilingual_runtime_error(
                "元数据 Raft 成员变更中止失败",
                format!("metadata raft membership abort failed: {err}"),
            ));
        }

        Ok(self.metadata_raft_status().await)
    }

    pub async fn finalize_metadata_membership_change(&self) -> Result<MetadataRaftStatus, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let network_enabled = Self::metadata_network_enabled();
        let (finalize_snapshot, rollback_snapshot) = {
            let mut raft = self.metadata_raft.write().await;
            if raft.membership_phase != "joint" {
                return Err(bilingual_runtime_error(
                    "当前无进行中的元数据 Raft joint-consensus 变更",
                    "no metadata raft joint-consensus change in progress",
                ));
            }
            if !Self::local_peer_in_membership(&raft, &local_peer_id) {
                return Err(bilingual_runtime_error(
                    "当前节点不在元数据 Raft 成员集合中",
                    "local peer is not in metadata raft membership",
                ));
            }
            if network_enabled && raft.leader_id != local_peer_id {
                return Err(bilingual_runtime_error(
                    "仅 Raft leader 可完成成员变更",
                    format!(
                        "metadata raft membership finalize must be issued on leader {}, local peer is {}",
                        raft.leader_id, local_peer_id
                    ),
                ));
            }

            let new_members = Self::canonical_member_ids(raft.joint_new_members.clone());
            if new_members.is_empty() {
                return Err(bilingual_runtime_error(
                    "joint-consensus 新成员集合为空，无法完成",
                    "joint-consensus new membership set is empty and cannot be finalized",
                ));
            }

            let rollback_snapshot = raft.clone();
            let mut merged_peers = new_members
                .iter()
                .map(|member_id| {
                    if let Some(existing) = raft.peers.iter().find(|peer| &peer.id == member_id) {
                        return existing.clone();
                    }
                    let peer_path = Self::metadata_raft_root_dir(&self.data_dir).join(member_id);
                    let _ = std::fs::create_dir_all(&peer_path);
                    MetadataRaftPeer {
                        id: member_id.clone(),
                        path: peer_path,
                        endpoint: Self::metadata_peer_endpoints().get(member_id).cloned(),
                        online: false,
                        match_index: raft.commit_index,
                        next_index: raft.commit_index.saturating_add(1),
                        last_index: raft.commit_index,
                    }
                })
                .collect::<Vec<_>>();
            merged_peers.sort_by(|left, right| left.id.cmp(&right.id));

            raft.peers = merged_peers;
            raft.membership_phase = "stable".to_string();
            raft.joint_old_members.clear();
            raft.joint_new_members.clear();
            Self::elect_metadata_raft_leader_if_needed(&mut raft);
            raft.last_error = None;
            (raft.clone(), rollback_snapshot)
        };
        self.persist_metadata_raft_state_inner(&finalize_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-joint-manual-finalize").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                *raft = rollback_snapshot.clone();
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 成员变更完成失败",
                    format!("metadata raft membership finalize failed: {err}"),
                ));
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            return Err(bilingual_runtime_error(
                "元数据 Raft 成员变更完成失败",
                format!("metadata raft membership finalize failed: {err}"),
            ));
        }

        Ok(self.metadata_raft_status().await)
    }

    pub async fn add_metadata_peer(
        &self,
        peer_id: &str,
        endpoint: Option<String>,
        online: bool,
        auto_finalize: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let id = peer_id.trim();
        if !Self::metadata_peer_id_valid(id) {
            return Err(bilingual_runtime_error(
                "元数据 Raft 节点 ID 无效",
                "invalid metadata raft peer id",
            ));
        }
        let endpoint = endpoint
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if let Some(value) = endpoint.as_ref() {
            if !Self::metadata_peer_endpoint_valid(value) {
                return Err(bilingual_runtime_error(
                    "元数据 Raft 节点 endpoint 无效",
                    "invalid metadata raft peer endpoint",
                ));
            }
        }
        let start_snapshot = {
            let mut raft = self.metadata_raft.write().await;
            if raft.membership_phase == "joint" {
                return Err(bilingual_runtime_error(
                    "已有元数据 Raft 成员变更进行中",
                    "metadata raft joint-consensus change already in progress",
                ));
            }
            if raft.peers.iter().any(|peer| peer.id == id) {
                return Err(bilingual_runtime_error(
                    "元数据 Raft 节点已存在",
                    "metadata raft peer already exists",
                ));
            }

            let old_members = Self::canonical_member_ids(
                raft.peers
                    .iter()
                    .map(|peer| peer.id.clone())
                    .collect::<Vec<_>>(),
            );
            let peer_path = Self::metadata_raft_root_dir(&self.data_dir).join(id);
            std::fs::create_dir_all(&peer_path).map_err(|err| err.to_string())?;
            let commit_index = raft.commit_index;
            raft.peers.push(MetadataRaftPeer {
                id: id.to_string(),
                path: peer_path,
                endpoint,
                online,
                match_index: commit_index,
                next_index: commit_index.saturating_add(1),
                last_index: commit_index,
            });
            raft.peers.sort_by(|left, right| left.id.cmp(&right.id));
            let new_members = Self::canonical_member_ids(
                raft.peers
                    .iter()
                    .map(|peer| peer.id.clone())
                    .collect::<Vec<_>>(),
            );

            let old_quorum = Self::metadata_membership_quorum(old_members.len());
            let new_quorum = Self::metadata_membership_quorum(new_members.len());
            let old_online = Self::online_member_count(&raft, &old_members);
            let new_online = Self::online_member_count(&raft, &new_members);
            if old_online < old_quorum || new_online < new_quorum {
                raft.peers.retain(|peer| peer.id != id);
                return Err(bilingual_runtime_error(
                    "新增后无法满足 joint-consensus 法定票数",
                    format!(
                        "joint membership quorum would be invalid after add: old {old_online}/{old_quorum}, new {new_online}/{new_quorum}"
                    ),
                ));
            }

            raft.membership_phase = "joint".to_string();
            raft.joint_old_members = old_members;
            raft.joint_new_members = new_members;
            raft.last_error = None;
            raft.clone()
        };
        self.persist_metadata_raft_state_inner(&start_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-add-joint-start").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                raft.peers.retain(|peer| peer.id != id);
                raft.membership_phase = "stable".to_string();
                raft.joint_old_members.clear();
                raft.joint_new_members.clear();
                raft.last_error = Some(err.clone());
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            return Err(err);
        }
        if !auto_finalize {
            return Ok(self.metadata_raft_status().await);
        }

        let (finalize_snapshot, rollback_joint_snapshot) = {
            let mut raft = self.metadata_raft.write().await;
            if !raft.peers.iter().any(|peer| peer.id == id) {
                return Err(bilingual_runtime_error(
                    "元数据 Raft 节点不存在",
                    "metadata raft peer not found when finalizing add",
                ));
            }
            let rollback_snapshot = raft.clone();
            raft.membership_phase = "stable".to_string();
            raft.joint_old_members.clear();
            raft.joint_new_members.clear();
            Self::elect_metadata_raft_leader_if_needed(&mut raft);
            raft.last_error = None;
            (raft.clone(), rollback_snapshot)
        };
        self.persist_metadata_raft_state_inner(&finalize_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-add-joint-finalize").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                *raft = rollback_joint_snapshot.clone();
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 成员变更 finalize 失败，已回滚到 joint 阶段",
                    format!("peer-add finalize failed and rolled back to joint phase: {err}"),
                ));
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            let _ = self.sync_metadata_raft("peer-add-joint-rollback").await;
            return Err(bilingual_runtime_error(
                "元数据 Raft 成员变更 finalize 失败",
                format!("peer-add joint-finalize failed: {err}"),
            ));
        }

        Ok(self.metadata_raft_status().await)
    }

    pub async fn remove_metadata_peer(
        &self,
        peer_id: &str,
        auto_finalize: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let id = peer_id.trim();
        if id.is_empty() {
            return Err(bilingual_runtime_error(
                "元数据 Raft 节点 ID 不能为空",
                "metadata raft peer id cannot be empty",
            ));
        }
        let local_peer = Self::metadata_local_peer_id();
        if id == local_peer {
            return Err(bilingual_runtime_error(
                "不允许移除本地元数据 Raft 节点",
                "cannot remove local metadata raft peer",
            ));
        }
        let start_snapshot = {
            let mut raft = self.metadata_raft.write().await;
            if raft.membership_phase == "joint" {
                return Err(bilingual_runtime_error(
                    "已有元数据 Raft 成员变更进行中",
                    "metadata raft joint-consensus change already in progress",
                ));
            }
            if raft.peers.len() <= 1 {
                return Err(bilingual_runtime_error(
                    "至少保留一个元数据 Raft 节点",
                    "at least one metadata raft peer is required",
                ));
            }
            if !raft.peers.iter().any(|peer| peer.id == id) {
                return Err(bilingual_runtime_error(
                    "未找到元数据 Raft 节点",
                    "metadata raft peer not found",
                ));
            }

            let old_members = Self::canonical_member_ids(
                raft.peers
                    .iter()
                    .map(|peer| peer.id.clone())
                    .collect::<Vec<_>>(),
            );
            let new_members = Self::canonical_member_ids(
                raft.peers
                    .iter()
                    .filter(|peer| peer.id != id)
                    .map(|peer| peer.id.clone())
                    .collect::<Vec<_>>(),
            );
            if new_members.is_empty() {
                return Err(bilingual_runtime_error(
                    "至少保留一个元数据 Raft 节点",
                    "at least one metadata raft peer is required",
                ));
            }

            let old_quorum = Self::metadata_membership_quorum(old_members.len());
            let new_quorum = Self::metadata_membership_quorum(new_members.len());
            let old_online = Self::online_member_count(&raft, &old_members);
            let new_online = Self::online_member_count(&raft, &new_members);
            if old_online < old_quorum || new_online < new_quorum {
                return Err(bilingual_runtime_error(
                    "移除后无法满足 joint-consensus 法定票数",
                    format!(
                        "joint membership quorum would be invalid after remove: old {old_online}/{old_quorum}, new {new_online}/{new_quorum}"
                    ),
                ));
            }

            raft.membership_phase = "joint".to_string();
            raft.joint_old_members = old_members;
            raft.joint_new_members = new_members;
            raft.last_error = None;
            raft.clone()
        };
        self.persist_metadata_raft_state_inner(&start_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-remove-joint-start").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                raft.membership_phase = "stable".to_string();
                raft.joint_old_members.clear();
                raft.joint_new_members.clear();
                raft.last_error = Some(err.clone());
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            return Err(err);
        }
        if !auto_finalize {
            return Ok(self.metadata_raft_status().await);
        }

        let (finalize_snapshot, rollback_joint_snapshot) = {
            let mut raft = self.metadata_raft.write().await;
            let Some(index) = raft.peers.iter().position(|peer| peer.id == id) else {
                return Err(bilingual_runtime_error(
                    "未找到元数据 Raft 节点",
                    "metadata raft peer not found",
                ));
            };
            let rollback_snapshot = raft.clone();
            raft.peers.remove(index);
            raft.membership_phase = "stable".to_string();
            raft.joint_old_members.clear();
            raft.joint_new_members.clear();
            Self::elect_metadata_raft_leader_if_needed(&mut raft);
            raft.last_error = None;
            (raft.clone(), rollback_snapshot)
        };
        self.persist_metadata_raft_state_inner(&finalize_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-remove-joint-finalize").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                *raft = rollback_joint_snapshot.clone();
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 成员变更 finalize 失败，已回滚到 joint 阶段",
                    format!("peer-remove finalize failed and rolled back to joint phase: {err}"),
                ));
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            let _ = self.sync_metadata_raft("peer-remove-joint-rollback").await;
            return Err(bilingual_runtime_error(
                "元数据 Raft 成员变更 finalize 失败",
                format!("peer-remove joint-finalize failed: {err}"),
            ));
        }

        Ok(self.metadata_raft_status().await)
    }

    pub async fn elect_metadata_leader(
        &self,
        candidate_id: &str,
    ) -> Result<MetadataRaftStatus, String> {
        let candidate = candidate_id.trim();
        if candidate.is_empty() {
            return Err(bilingual_runtime_error(
                "候选节点不能为空",
                "raft election candidate cannot be empty",
            ));
        }
        let local_peer = Self::metadata_local_peer_id();
        let network_enabled = Self::metadata_network_enabled();
        if network_enabled && candidate != local_peer {
            return Err(bilingual_runtime_error(
                "请在候选节点本机发起选主",
                "in network mode election must be requested on candidate node",
            ));
        }

        let (cluster_id, term, quorum, candidate_last_index, candidate_last_term, peers) = {
            let raft = self.metadata_raft.read().await;
            let Some(candidate_peer) = raft.peers.iter().find(|peer| peer.id == candidate) else {
                return Err(bilingual_runtime_error(
                    "未找到候选元数据 Raft 节点",
                    "candidate metadata raft peer not found",
                ));
            };
            if !candidate_peer.online {
                return Err(bilingual_runtime_error(
                    "候选元数据 Raft 节点不在线",
                    "candidate metadata raft peer is offline",
                ));
            }
            let quorum = raft.peers.len() / 2 + 1;
            let online_peers = raft.peers.iter().filter(|item| item.online).count();
            if online_peers < quorum {
                return Err(bilingual_runtime_error(
                    "当前在线节点不足法定票数",
                    format!("online peers below quorum: {online_peers}/{quorum}"),
                ));
            }
            let max_online_index = raft
                .peers
                .iter()
                .filter(|peer| peer.online)
                .map(|peer| peer.last_index)
                .max()
                .unwrap_or(0);
            if candidate_peer.last_index < max_online_index {
                return Err(bilingual_runtime_error(
                    "候选节点日志落后，拒绝选主",
                    format!(
                        "candidate peer log is stale: {} < {}",
                        candidate_peer.last_index, max_online_index
                    ),
                ));
            }
            let last_commit_term = if raft.last_commit_term == 0 && raft.commit_index > 0 {
                raft.term
            } else {
                raft.last_commit_term
            };
            (
                raft.cluster_id.clone(),
                raft.term,
                quorum,
                raft.commit_index.max(candidate_peer.last_index),
                last_commit_term,
                raft.peers.clone(),
            )
        };

        if !network_enabled {
            let mut raft = self.metadata_raft.write().await;
            let now = Utc::now();
            if raft.leader_id != candidate {
                raft.leader_id = candidate.to_string();
                raft.term = raft.term.saturating_add(1);
                raft.voted_for = Some(candidate.to_string());
                raft.last_commit_at = Some(now);
                raft.last_error = None;
            }
            raft.last_election_at = Some(now);
            if candidate == local_peer {
                raft.last_heartbeat_at = Some(now);
            }
            raft.last_quorum_at = Some(now);
            let status = Self::metadata_raft_status_from_state(&raft);
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Ok(status);
        }

        let pre_vote_term = term.saturating_add(1);
        let mut pre_votes = 1usize;
        let mut max_term_seen = term;
        let mut last_error = None::<String>;
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|err| err.to_string())?;
        let internal_token = Self::internal_control_token();
        let pre_vote_request = MetadataRaftPreVoteRequest {
            cluster_id: cluster_id.clone(),
            candidate_id: candidate.to_string(),
            term: pre_vote_term,
            last_log_index: candidate_last_index,
            last_log_term: candidate_last_term,
        };
        for peer in peers.iter() {
            if !peer.online || peer.id == candidate {
                continue;
            }
            let Some(endpoint) = peer
                .endpoint
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            else {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 预投票失败",
                    format!("peer {} missing endpoint for pre-vote", peer.id),
                ));
                continue;
            };
            if !Self::metadata_peer_endpoint_valid(&endpoint) {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 预投票失败",
                    format!("peer {} endpoint is invalid", peer.id),
                ));
                continue;
            }
            let url = format!(
                "{}/api/v1/internal/metadata-raft/pre-vote",
                endpoint.trim_end_matches('/')
            );
            match Self::send_metadata_raft_pre_vote_request(
                &client,
                &url,
                &internal_token,
                &pre_vote_request,
            )
            .await
            {
                Ok(payload) => {
                    max_term_seen = max_term_seen.max(payload.term);
                    if payload.pre_vote_granted {
                        pre_votes += 1;
                    } else if let Some(reason) = payload.reason {
                        last_error =
                            Some(bilingual_runtime_error("元数据 Raft 预投票失败", reason));
                    }
                }
                Err(err) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 预投票失败",
                        format!("pre-vote request failed: {err}"),
                    ));
                }
            }
        }

        if pre_votes < quorum {
            let mut raft = self.metadata_raft.write().await;
            raft.term = raft.term.max(max_term_seen);
            raft.voted_for = None;
            raft.last_election_at = Some(Utc::now());
            raft.last_error = Some(last_error.unwrap_or_else(|| {
                bilingual_runtime_error(
                    "元数据 Raft 预投票未达到法定票数",
                    format!("pre-votes below quorum: {pre_votes}/{quorum}"),
                )
            }));
            let err = raft.last_error.clone().unwrap_or_else(|| {
                bilingual_runtime_error("元数据 Raft 预投票失败", "metadata raft pre-vote failed")
            });
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Err(err);
        }

        let election_term = pre_vote_term;
        let mut votes = 1usize;
        let vote_request = MetadataRaftVoteRequest {
            cluster_id: cluster_id.clone(),
            candidate_id: candidate.to_string(),
            term: election_term,
            last_log_index: candidate_last_index,
            last_log_term: candidate_last_term,
        };
        for peer in peers {
            if !peer.online || peer.id == candidate {
                continue;
            }
            let Some(endpoint) = peer
                .endpoint
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            else {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 选举失败",
                    format!("peer {} missing endpoint for vote", peer.id),
                ));
                continue;
            };
            if !Self::metadata_peer_endpoint_valid(&endpoint) {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 选举失败",
                    format!("peer {} endpoint is invalid", peer.id),
                ));
                continue;
            }
            let url = format!(
                "{}/api/v1/internal/metadata-raft/request-vote",
                endpoint.trim_end_matches('/')
            );
            match client
                .post(url)
                .header("x-rustio-internal-token", &internal_token)
                .json(&vote_request)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    match response.json::<MetadataRaftVoteResponse>().await {
                        Ok(payload) => {
                            max_term_seen = max_term_seen.max(payload.term);
                            if payload.vote_granted {
                                votes += 1;
                            } else if let Some(reason) = payload.reason {
                                last_error =
                                    Some(bilingual_runtime_error("元数据 Raft 选举失败", reason));
                            }
                        }
                        Err(err) => {
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 选举失败",
                                format!("decode vote response failed: {err}"),
                            ));
                        }
                    }
                }
                Ok(response) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 选举失败",
                        format!("vote request status: {}", response.status()),
                    ));
                }
                Err(err) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 选举失败",
                        format!("vote request failed: {err}"),
                    ));
                }
            }
        }

        if votes < quorum {
            let mut raft = self.metadata_raft.write().await;
            raft.term = raft.term.max(max_term_seen);
            raft.voted_for = None;
            raft.last_election_at = Some(Utc::now());
            raft.last_error = Some(last_error.unwrap_or_else(|| {
                bilingual_runtime_error(
                    "元数据 Raft 选举失败",
                    format!("votes below quorum: {votes}/{quorum}"),
                )
            }));
            let err = raft.last_error.clone().unwrap_or_else(|| {
                bilingual_runtime_error("元数据 Raft 选举失败", "raft election failed")
            });
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Err(err);
        }

        let mut raft = self.metadata_raft.write().await;
        let now = Utc::now();
        raft.term = raft.term.max(election_term);
        raft.leader_id = candidate.to_string();
        raft.voted_for = Some(candidate.to_string());
        raft.last_commit_at = Some(now);
        raft.last_election_at = Some(now);
        if candidate == local_peer {
            raft.last_heartbeat_at = Some(now);
        }
        raft.last_quorum_at = Some(now);
        raft.last_error = None;
        let status = Self::metadata_raft_status_from_state(&raft);
        let raft_snapshot = raft.clone();
        drop(raft);
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        Ok(status)
    }

    pub async fn handle_metadata_pre_vote_request(
        &self,
        request: MetadataRaftPreVoteRequest,
    ) -> Result<MetadataRaftPreVoteResponse, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let raft = self.metadata_raft.read().await;
        if raft.cluster_id != request.cluster_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 集群标识不匹配",
                format!(
                    "metadata raft cluster mismatch: expected {}, got {}",
                    raft.cluster_id, request.cluster_id
                ),
            ));
        }
        if !Self::local_peer_in_membership(&raft, &local_peer_id) {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("local peer not in membership".to_string()),
            });
        }

        if request.term < raft.term {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate term is stale".to_string()),
            });
        }

        let candidate_peer = raft
            .peers
            .iter()
            .find(|peer| peer.id == request.candidate_id);
        let Some(candidate_peer) = candidate_peer else {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate peer not found".to_string()),
            });
        };
        if !candidate_peer.online {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate peer is offline".to_string()),
            });
        }

        let local_last_term = if raft.last_commit_term == 0 && raft.commit_index > 0 {
            raft.term
        } else {
            raft.last_commit_term
        };
        let local_last_index = raft.commit_index;
        if request.last_log_term < local_last_term {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate log term is stale".to_string()),
            });
        }
        if request.last_log_term == local_last_term && request.last_log_index < local_last_index {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate log index is stale".to_string()),
            });
        }

        Ok(MetadataRaftPreVoteResponse {
            term: raft.term,
            pre_vote_granted: true,
            reason: None,
        })
    }

    pub async fn handle_metadata_vote_request(
        &self,
        request: MetadataRaftVoteRequest,
    ) -> Result<MetadataRaftVoteResponse, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let mut raft = self.metadata_raft.write().await;
        if raft.cluster_id != request.cluster_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 集群标识不匹配",
                format!(
                    "metadata raft cluster mismatch: expected {}, got {}",
                    raft.cluster_id, request.cluster_id
                ),
            ));
        }
        if !Self::local_peer_in_membership(&raft, &local_peer_id) {
            return Ok(MetadataRaftVoteResponse {
                term: raft.term,
                vote_granted: false,
                reason: Some("local peer not in membership".to_string()),
            });
        }

        let mut changed = false;
        let response = if request.term < raft.term {
            MetadataRaftVoteResponse {
                term: raft.term,
                vote_granted: false,
                reason: Some("candidate term is stale".to_string()),
            }
        } else {
            if request.term > raft.term {
                raft.term = request.term;
                raft.leader_id.clear();
                raft.voted_for = None;
                changed = true;
            }

            let candidate_peer = raft
                .peers
                .iter()
                .find(|peer| peer.id == request.candidate_id);
            if candidate_peer.is_none() {
                MetadataRaftVoteResponse {
                    term: raft.term,
                    vote_granted: false,
                    reason: Some("candidate peer not found".to_string()),
                }
            } else if !candidate_peer.map(|peer| peer.online).unwrap_or(false) {
                MetadataRaftVoteResponse {
                    term: raft.term,
                    vote_granted: false,
                    reason: Some("candidate peer is offline".to_string()),
                }
            } else {
                let local_last_term = if raft.last_commit_term == 0 && raft.commit_index > 0 {
                    raft.term
                } else {
                    raft.last_commit_term
                };
                let local_last_index = raft.commit_index;
                if request.last_log_term < local_last_term {
                    MetadataRaftVoteResponse {
                        term: raft.term,
                        vote_granted: false,
                        reason: Some("candidate log term is stale".to_string()),
                    }
                } else if request.last_log_term == local_last_term
                    && request.last_log_index < local_last_index
                {
                    MetadataRaftVoteResponse {
                        term: raft.term,
                        vote_granted: false,
                        reason: Some("candidate log index is stale".to_string()),
                    }
                } else if let Some(voted_for) = raft.voted_for.as_ref() {
                    if voted_for != &request.candidate_id {
                        MetadataRaftVoteResponse {
                            term: raft.term,
                            vote_granted: false,
                            reason: Some("already voted for another candidate".to_string()),
                        }
                    } else {
                        raft.last_error = None;
                        MetadataRaftVoteResponse {
                            term: raft.term,
                            vote_granted: true,
                            reason: None,
                        }
                    }
                } else {
                    raft.voted_for = Some(request.candidate_id);
                    raft.last_error = None;
                    changed = true;
                    MetadataRaftVoteResponse {
                        term: raft.term,
                        vote_granted: true,
                        reason: None,
                    }
                }
            }
        };
        let raft_snapshot = changed.then(|| raft.clone());
        drop(raft);
        if let Some(raft_snapshot) = raft_snapshot {
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        }
        Ok(response)
    }

    pub async fn handle_metadata_heartbeat_request(
        &self,
        request: MetadataRaftHeartbeatRequest,
    ) -> Result<MetadataRaftHeartbeatResponse, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let mut raft = self.metadata_raft.write().await;
        if raft.cluster_id != request.cluster_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 集群标识不匹配",
                format!(
                    "metadata raft cluster mismatch: expected {}, got {}",
                    raft.cluster_id, request.cluster_id
                ),
            ));
        }
        if !Self::local_peer_in_membership(&raft, &local_peer_id) {
            return Ok(MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: false,
                reason: Some("local peer not in membership".to_string()),
            });
        }

        let mut changed = false;
        let response = if request.term < raft.term {
            MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: false,
                reason: Some("leader term is stale".to_string()),
            }
        } else if request.leader_id.trim().is_empty() {
            MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: false,
                reason: Some("leader id is empty".to_string()),
            }
        } else if let Some(leader_index) = raft
            .peers
            .iter()
            .position(|peer| peer.id == request.leader_id)
        {
            let local_last_index = raft
                .peers
                .iter()
                .find(|peer| peer.id == local_peer_id)
                .map(|peer| peer.last_index)
                .unwrap_or(raft.commit_index);

            if request.term > raft.term {
                raft.term = request.term;
                raft.voted_for = None;
            }
            if raft.leader_id != request.leader_id {
                raft.leader_id = request.leader_id.clone();
            }
            let leader_peer = &mut raft.peers[leader_index];
            if !leader_peer.online {
                leader_peer.online = true;
            }

            let target_commit = request
                .leader_commit
                .min(local_last_index.max(raft.commit_index));
            if target_commit > raft.commit_index {
                raft.commit_index = target_commit;
                if request.term >= raft.last_commit_term {
                    raft.last_commit_term = request.term;
                }
            }
            if request.term >= raft.last_commit_term {
                raft.last_commit_term = request.term;
            }
            raft.last_heartbeat_at = Some(Utc::now());
            raft.last_error = None;
            changed = true;

            MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: true,
                reason: None,
            }
        } else {
            MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: false,
                reason: Some("leader peer not found".to_string()),
            }
        };

        let raft_snapshot = changed.then(|| raft.clone());
        drop(raft);
        if let Some(raft_snapshot) = raft_snapshot {
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        }
        Ok(response)
    }

    pub(crate) async fn apply_metadata_raft_snapshot_internal(
        &self,
        request: MetadataRaftSyncRequest,
        persist_to_disk: bool,
    ) -> Result<MetadataRaftSyncResponse, String> {
        let applied_match_index = request.entry.index;
        let leader_commit = if request.leader_commit == 0 {
            request.entry.index
        } else {
            request.leader_commit.min(request.entry.index)
        };
        let raft_snapshot = {
            let mut raft = self.metadata_raft.write().await;
            if raft.cluster_id != request.cluster_id {
                return Err(bilingual_runtime_error(
                    "元数据 Raft 集群标识不匹配",
                    format!(
                        "metadata raft cluster mismatch: expected {}, got {}",
                        raft.cluster_id, request.cluster_id
                    ),
                ));
            }

            let local_commit_index = raft.commit_index;
            let local_commit_term = Self::raft_last_commit_term(&raft);
            if request.entry.term < raft.term && persist_to_disk {
                return Ok(MetadataRaftSyncResponse {
                    term: raft.term,
                    success: false,
                    match_index: local_commit_index,
                    reason: Some("stale leader term".to_string()),
                });
            }
            if !request.install_snapshot {
                if request.prev_log_index > local_commit_index {
                    return Ok(MetadataRaftSyncResponse {
                        term: raft.term,
                        success: false,
                        match_index: local_commit_index,
                        reason: Some("missing previous log entry".to_string()),
                    });
                }
                if request.prev_log_index == local_commit_index
                    && request.prev_log_index > 0
                    && request.prev_log_term != local_commit_term
                {
                    return Ok(MetadataRaftSyncResponse {
                        term: raft.term,
                        success: false,
                        match_index: local_commit_index,
                        reason: Some("prev log term mismatch".to_string()),
                    });
                }
            }
            if request.entry.index < local_commit_index {
                return Ok(MetadataRaftSyncResponse {
                    term: raft.term,
                    success: true,
                    match_index: local_commit_index,
                    reason: Some("already up-to-date".to_string()),
                });
            }
            if request.entry.index == local_commit_index {
                if persist_to_disk && request.entry.term < local_commit_term {
                    return Ok(MetadataRaftSyncResponse {
                        term: raft.term,
                        success: false,
                        match_index: local_commit_index,
                        reason: Some("incoming entry term is stale".to_string()),
                    });
                }
                if !request.install_snapshot
                    && !raft.last_snapshot_hash.is_empty()
                    && !request.entry.snapshot_hash.is_empty()
                    && request.entry.snapshot_hash != raft.last_snapshot_hash
                {
                    return Ok(MetadataRaftSyncResponse {
                        term: raft.term,
                        success: false,
                        match_index: local_commit_index,
                        reason: Some("conflicting snapshot at same index".to_string()),
                    });
                }
            }

            let target_path = if let Some(peer) = raft
                .peers
                .iter_mut()
                .find(|peer| peer.id == request.peer_id)
            {
                peer.last_index = peer.last_index.max(request.entry.index);
                peer.match_index = peer.match_index.max(peer.last_index);
                peer.next_index = peer.match_index.saturating_add(1);
                peer.path.clone()
            } else {
                let peer_dir = self
                    .data_dir
                    .join(".rustio_meta_raft")
                    .join(request.peer_id.clone());
                let _ = std::fs::create_dir_all(&peer_dir);
                raft.peers.push(MetadataRaftPeer {
                    id: request.peer_id.clone(),
                    path: peer_dir.clone(),
                    endpoint: None,
                    online: true,
                    match_index: request.entry.index,
                    next_index: request.entry.index.saturating_add(1),
                    last_index: request.entry.index,
                });
                peer_dir
            };

            if persist_to_disk {
                let snapshot_bytes =
                    serde_json::to_vec_pretty(&request.snapshot).map_err(|err| err.to_string())?;
                Self::persist_metadata_log_to_peer(&target_path, &request.entry, &snapshot_bytes)?;
            }

            if request.entry.term > raft.term {
                raft.voted_for = None;
            }
            let incoming_term = request.entry.term;
            if leader_commit > raft.commit_index
                || (leader_commit == raft.commit_index && incoming_term > raft.last_commit_term)
            {
                raft.last_commit_term = incoming_term;
            }
            raft.term = raft.term.max(incoming_term);
            raft.commit_index = raft.commit_index.max(leader_commit);
            raft.last_snapshot_hash = request.entry.snapshot_hash.clone();
            raft.last_commit_at = Some(request.entry.written_at);
            raft.last_error = None;
            raft.clone()
        };
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;

        let snapshot = request.snapshot;
        {
            let mut buckets = HashMap::new();
            for bucket in snapshot.buckets {
                buckets.insert(bucket.name.clone(), bucket);
            }
            *self.buckets.write().await = buckets;
        }
        *self.remote_tiers.write().await =
            snapshot.remote_tiers.into_iter().collect::<HashMap<_, _>>();
        *self.bucket_object_locks.write().await = snapshot
            .bucket_object_locks
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_retentions.write().await = snapshot
            .bucket_retentions
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_legal_holds.write().await = snapshot
            .bucket_legal_holds
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_notifications.write().await = snapshot
            .bucket_notifications
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_lifecycle_rules.write().await = snapshot
            .bucket_lifecycle_rules
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_acls.write().await =
            snapshot.bucket_acls.into_iter().collect::<HashMap<_, _>>();
        *self.bucket_public_access_blocks.write().await = snapshot
            .bucket_public_access_blocks
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_policies.write().await = snapshot
            .bucket_policies
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_cors_rules.write().await = snapshot
            .bucket_cors_rules
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_tags.write().await =
            snapshot.bucket_tags.into_iter().collect::<HashMap<_, _>>();
        *self.bucket_encryptions.write().await = snapshot
            .bucket_encryptions
            .into_iter()
            .collect::<HashMap<_, _>>();
        // 对象元数据不再从 Raft 快照恢复(redb 持久化,启动时从 redb 灌入 DashMap)。
        *self.credentials.write().await =
            snapshot.credentials.into_iter().collect::<HashMap<_, _>>();
        *self.users.write().await = snapshot.iam_users;
        *self.groups.write().await = snapshot.iam_groups;
        *self.policies.write().await = snapshot.iam_policies;
        *self.service_accounts.write().await = snapshot.service_accounts;
        *self.admin_sessions.write().await = snapshot.admin_sessions.clone();
        Self::persist_console_sessions_snapshot(&self.data_dir, &snapshot.admin_sessions)?;
        *self.sts_sessions.write().await = snapshot.sts_sessions;
        *self.replications.write().await = snapshot.replications;
        *self.site_replications.write().await = snapshot.site_replications;
        *self.replication_backlog.write().await = snapshot.replication_backlog;
        *self.replication_checkpoints.write().await = snapshot
            .replication_checkpoints
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.cluster_config_history.write().await = snapshot.cluster_config_history.clone();
        Self::persist_cluster_config_history_snapshot(
            &self.data_dir,
            &snapshot.cluster_config_history,
        )?;
        *self.security.write().await = snapshot.security.clone();
        Self::persist_security_config_snapshot(&self.data_dir, &snapshot.security)?;
        *self.jobs.write().await = snapshot.jobs;
        self.persist_replication_runtime_state().await;
        Ok(MetadataRaftSyncResponse {
            term: raft_snapshot.term,
            success: true,
            match_index: applied_match_index,
            reason: None,
        })
    }

    pub async fn apply_remote_metadata_raft_sync(
        &self,
        request: MetadataRaftSyncRequest,
    ) -> Result<MetadataRaftSyncResponse, String> {
        self.apply_metadata_raft_snapshot_internal(request, true)
            .await
    }
}
