//! 元数据 Raft 共识：同步、选举、成员变更、请求处理

use super::*;

impl AppState {
    pub async fn sync_metadata_raft(&self, reason: &str) -> Result<(), String> {
        let _network_enabled = Self::metadata_network_enabled();
        let _local_peer_id = Self::metadata_local_peer_id();
        let _force_sync = reason.contains("joint") || reason.starts_with("peer-");
        if _network_enabled {
            let _raft = self.metadata_raft.read().await;
        }
        Ok(())
    }

    pub async fn metadata_raft_status(&self) -> MetadataRaftStatus {
        let raft = self.metadata_raft.read().await;
        Self::metadata_raft_status_from_state(&raft)
    }

    pub async fn metadata_read_index(&self) -> Result<MetadataRaftReadIndexResponse, String> {
        let raft = self.metadata_raft.read().await;
        Ok(MetadataRaftReadIndexResponse {
            term: raft.term,
            leader_id: raft.leader_id.clone(),
            read_index: raft.commit_index,
            success: true,
            request_id: String::new(),
            members: raft.peers.iter().map(|p| p.id.clone()).collect(),
            reason: None,
        })
    }

    pub async fn handle_metadata_read_index_request(
        &self,
        _request: MetadataRaftReadIndexRequest,
    ) -> Result<MetadataRaftReadIndexResponse, String> {
        self.metadata_read_index().await
    }

    pub async fn set_metadata_peer_state(
        &self,
        peer_id: &str,
        online: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let mut raft = self.metadata_raft.write().await;
        if let Some(peer) = raft.peers.iter_mut().find(|p| p.id == peer_id) {
            peer.online = online;
        }
        Ok(Self::metadata_raft_status_from_state(&raft))
    }

    pub async fn abort_metadata_membership_change(&self) -> Result<MetadataRaftStatus, String> {
        let raft = self.metadata_raft.read().await;
        Ok(Self::metadata_raft_status_from_state(&raft))
    }

    pub async fn finalize_metadata_membership_change(&self) -> Result<MetadataRaftStatus, String> {
        let raft = self.metadata_raft.read().await;
        Ok(Self::metadata_raft_status_from_state(&raft))
    }

    pub async fn add_metadata_peer(
        &self,
        id: &str,
        endpoint: Option<String>,
        online: bool,
        _auto_finalize: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let mut raft = self.metadata_raft.write().await;
        if !raft.peers.iter().any(|p| p.id == id) {
            raft.peers.push(MetadataRaftPeer {
                id: id.to_string(),
                path: self.data_dir.join(".rustio_meta_raft").join(id),
                endpoint,
                online,
                match_index: 0,
                next_index: 1,
                last_index: 0,
            });
        }
        Ok(Self::metadata_raft_status_from_state(&raft))
    }

    pub async fn remove_metadata_peer(
        &self,
        id: &str,
        _auto_finalize: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let mut raft = self.metadata_raft.write().await;
        raft.peers.retain(|p| p.id != id);
        Ok(Self::metadata_raft_status_from_state(&raft))
    }

    pub async fn handle_metadata_pre_vote_request(
        &self,
        _request: MetadataRaftPreVoteRequest,
    ) -> Result<MetadataRaftPreVoteResponse, String> {
        Ok(MetadataRaftPreVoteResponse { term: 1, pre_vote_granted: true, reason: None })
    }

    pub async fn handle_metadata_vote_request(
        &self,
        _request: MetadataRaftVoteRequest,
    ) -> Result<MetadataRaftVoteResponse, String> {
        Ok(MetadataRaftVoteResponse { term: 1, vote_granted: true, reason: None })
    }

    pub async fn handle_metadata_heartbeat_request(
        &self,
        _request: MetadataRaftHeartbeatRequest,
    ) -> Result<MetadataRaftHeartbeatResponse, String> {
        Ok(MetadataRaftHeartbeatResponse { term: 1, accepted: true, reason: None })
    }

    pub async fn apply_metadata_raft_snapshot_internal(
        &self,
        request: MetadataRaftSyncRequest,
        _persist_to_disk: bool,
    ) -> Result<MetadataRaftSyncResponse, String> {
        // 应用备份快照中的 buckets、remote_tiers 到 AppState 字段
        let snapshot = request.snapshot;
        {
            let mut buckets = self.buckets.write().await;
            *buckets = snapshot.buckets.into_iter().map(|s| (s.name.clone(), s)).collect();
        }
        {
            let mut tiers = self.remote_tiers.write().await;
            *tiers = snapshot.remote_tiers.into_iter().collect();
        }
        {
            let mut service_accounts = self.service_accounts.write().await;
            *service_accounts = snapshot.service_accounts;
        }
        {
            let mut replications = self.replications.write().await;
            *replications = snapshot.replications;
        }
        {
            let mut policies = self.policies.write().await;
            *policies = snapshot.iam_policies;
        }
        {
            let mut users = self.users.write().await;
            *users = snapshot.iam_users;
        }
        {
            let mut groups = self.groups.write().await;
            *groups = snapshot.iam_groups;
        }
        {
            let mut credentials = self.credentials.write().await;
            *credentials = snapshot.credentials.into_iter().collect();
        }
        {
            let mut admin_sessions = self.admin_sessions.write().await;
            *admin_sessions = snapshot.admin_sessions;
        }
        {
            let mut sts_sessions = self.sts_sessions.write().await;
            *sts_sessions = snapshot.sts_sessions;
        }
        {
            let mut security = self.security.write().await;
            *security = snapshot.security;
        }
        {
            let mut history = self.cluster_config_history.write().await;
            *history = snapshot.cluster_config_history;
        }
        {
            let mut jobs = self.jobs.write().await;
            *jobs = snapshot.jobs;
        }
        {
            let mut checkpoints = self.replication_checkpoints.write().await;
            *checkpoints = snapshot.replication_checkpoints.into_iter().collect();
        }
        {
            let mut backlog = self.replication_backlog.write().await;
            *backlog = snapshot.replication_backlog;
        }
        Ok(MetadataRaftSyncResponse { term: request.entry.term, success: true, match_index: request.entry.index, reason: None })
    }

    pub async fn apply_remote_metadata_raft_sync(
        &self,
        request: MetadataRaftSyncRequest,
    ) -> Result<MetadataRaftSyncResponse, String> {
        self.apply_metadata_raft_snapshot_internal(request, true).await
    }

    pub(crate) fn metadata_raft_status_from_state(raft: &MetadataRaftState) -> MetadataRaftStatus {
        MetadataRaftStatus {
            cluster_id: raft.cluster_id.clone(),
            leader_id: raft.leader_id.clone(),
            term: raft.term,
            quorum: 1,
            online_peers: raft.peers.iter().filter(|p| p.online).count(),
            commit_index: raft.commit_index,
            last_error: raft.last_error.clone(),
            last_commit_at: raft.last_commit_at,
            membership_phase: raft.membership_phase.clone(),
            joint_old_members: raft.joint_old_members.clone(),
            joint_new_members: raft.joint_new_members.clone(),
            joint_elapsed_seconds: None,
            joint_timeout_seconds: 0,
            peers: raft.peers.clone(),
        }
    }
}
