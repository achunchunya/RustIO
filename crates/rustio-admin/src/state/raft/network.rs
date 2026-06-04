//! 单节点阶段的占位 RaftNetwork。多节点 HTTP 传输在阶段③实现。
//!
//! 单节点集群(单成员)不会触发节点间 RPC,故这里 unimplemented;阶段③改为
//! 复用现有 `internal.rs` 的 HTTP + token 传输,实现 append_entries/install_snapshot/vote。

use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, RaftNetwork, RaftNetworkFactory};

use super::TypeConfig;

pub(crate) struct NetworkFactory;

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = NetworkConn;

    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Self::Network {
        NetworkConn {
            target,
            addr: node.addr.clone(),
        }
    }
}

pub(crate) struct NetworkConn {
    target: u64,
    addr: String,
}

impl RaftNetwork<TypeConfig> for NetworkConn {
    async fn append_entries(
        &mut self,
        _rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        // 阶段③:HTTP POST 到 target 的 /api/v1/internal/metadata-raft/append。单节点不触发。
        Err(RPCError::Network(NetworkError::new(&std::io::Error::other(
            format!("network not implemented (phase ③); target={}", self.target),
        ))))
    }

    async fn vote(
        &mut self,
        _rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        Err(RPCError::Network(NetworkError::new(&std::io::Error::other(
            format!("network not implemented (phase ③); addr={}", self.addr),
        ))))
    }

    async fn install_snapshot(
        &mut self,
        _rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        Err(RPCError::Network(NetworkError::new(&std::io::Error::other(
            "network not implemented (phase ③)",
        ))))
    }
}
