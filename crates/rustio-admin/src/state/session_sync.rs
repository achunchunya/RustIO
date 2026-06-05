//! 跨节点控制台会话同步（console session broadcast）。
//!
//! 广播到所有已知 peer 节点，跳过来源节点自身。
//! 认证复用 internal token 模式。

use crate::state::AppState;
use crate::state::ConsoleSession;
use reqwest::Client;

impl AppState {
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
            let url = format!("{endpoint}/api/v1/internal/auth/sessions/sync/{session_id}");
            let _ = client
                .delete(url)
                .header("x-rustio-internal-token", &internal_token)
                .send()
                .await;
        }
    }
}
