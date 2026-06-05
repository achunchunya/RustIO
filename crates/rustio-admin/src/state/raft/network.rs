//! openraft 网络层:通过 HTTP 向 peer 节点发送 RPC(append_entries/vote/install_snapshot)。
//!
//! `NetworkFactory` 持集群 peer 拓扑和内部认证 token,在 `new_client()` 时从 peer map
//! 查找目标节点的 api_addr,随后通过 reqwest 发 JSON 请求。
//! `NetworkConn` 的三种 RPC 方法分别对接 `/api/v1/internal/metadata-raft/{append|vote|install-snapshot}` 端点。

use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, RaftNetwork, RaftNetworkFactory};

use super::TypeConfig;

pub(crate) struct NetworkFactory {
    peer_api_addrs: std::collections::HashMap<u64, String>,
    internal_token: String,
}

impl NetworkFactory {
    pub(crate) fn new(
        peer_api_addrs: std::collections::HashMap<u64, String>,
        internal_token: String,
    ) -> Self {
        Self {
            peer_api_addrs,
            internal_token,
        }
    }
}

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = NetworkConn;

    async fn new_client(&mut self, target: u64, _node: &BasicNode) -> Self::Network {
        let addr = self
            .peer_api_addrs
            .get(&target)
            .cloned()
            .unwrap_or_default();
        NetworkConn {
            target,
            addr,
            internal_token: self.internal_token.clone(),
        }
    }
}

pub(crate) struct NetworkConn {
    target: u64,
    addr: String,
    internal_token: String,
}

impl NetworkConn {
    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }
}

impl RaftNetwork<TypeConfig> for NetworkConn {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let url = format!("{}/api/v1/internal/metadata-raft/append", self.addr);
        let resp = self
            .client()
            .post(&url)
            .header("x-rustio-internal-token", &self.internal_token)
            .json(&rpc)
            .send()
            .await
            .map_err(|err| {
                RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                    "append_entries to {} failed: {err}", self.target
                ))))
            })?;
        let body = resp.bytes().await.map_err(|err| {
            RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                "append_entries read body from {}: {err}", self.target
            ))))
        })?;
        serde_json::from_slice::<AppendEntriesResponse<u64>>(&body).map_err(|err| {
            RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                "append_entries deserialize from {}: {err}", self.target
            ))))
        })
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let url = format!("{}/api/v1/internal/metadata-raft/vote", self.addr);
        let resp = self
            .client()
            .post(&url)
            .header("x-rustio-internal-token", &self.internal_token)
            .json(&rpc)
            .send()
            .await
            .map_err(|err| {
                RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                    "vote to {} failed: {err}", self.target
                ))))
            })?;
        let body = resp.bytes().await.map_err(|err| {
            RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                "vote read body from {}: {err}", self.target
            ))))
        })?;
        serde_json::from_slice::<VoteResponse<u64>>(&body).map_err(|err| {
            RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                "vote deserialize from {}: {err}", self.target
            ))))
        })
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        let url = format!("{}/api/v1/internal/metadata-raft/install-snapshot", self.addr);
        let resp = self
            .client()
            .post(&url)
            .header("x-rustio-internal-token", &self.internal_token)
            .json(&rpc)
            .send()
            .await
            .map_err(|err| {
                RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                    "install_snapshot to {} failed: {err}", self.target
                ))))
            })?;
        let body = resp.bytes().await.map_err(|err| {
            RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                "install_snapshot read body from {}: {err}", self.target
            ))))
        })?;
        serde_json::from_slice::<InstallSnapshotResponse<u64>>(&body).map_err(|err| {
            RPCError::Network(NetworkError::new(&std::io::Error::other(format!(
                "install_snapshot deserialize from {}: {err}", self.target
            ))))
        })
    }
}
