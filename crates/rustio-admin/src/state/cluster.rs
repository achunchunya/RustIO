//! 集群拓扑:节点发现、磁盘映射、peer 端点解析。
//!
//! 单机模式(local_node_id = 0):不解析集群 env vars,所有磁盘视为本地。
//! 集群模式(local_node_id > 0):解析 RUSTIO_CLUSTER_NODE_ID / RUSTIO_CLUSTER_NODE_ADDR /
//! RUSTIO_CLUSTER_SEEDS,构建 ClusterPeerInfo 映射。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// 单个节点的集群信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterPeerInfo {
    pub node_id: u64,
    pub node_name: String,
    pub api_addr: String,
    pub zone: String,
    /// 该节点管理的本地磁盘（global_disk_id → 本地路径）。
    pub disks: Vec<ClusterDiskInfo>,
    /// 退役中标记:true 时不再接受新分片放置(优雅退役 draining 阶段),
    /// EC 布局/放置自动排除该节点,存量数据经 rebalance 迁出后再从成员集移除。
    #[serde(default)]
    pub draining: bool,
    /// 节点所属组(分片放置域)。同一组内的节点构成独立 EC 域;
    /// 不同组的节点互不可见于分片放置。默认 "default"(单组集群向后兼容)。
    #[serde(default = "default_group_id")]
    pub group_id: String,
}

fn default_group_id() -> String {
    "default".to_string()
}

/// 节点的单个本地磁盘（全局唯一 ID + 本地路径）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterDiskInfo {
    pub global_id: String,
    pub local_index: usize,
    pub local_path: PathBuf,
}

/// 集群拓扑配置（从环境变量解析）。
#[derive(Debug, Clone)]
pub(crate) struct ClusterConfig {
    pub local_node_id: u64,
    pub local_node_name: String,
    pub local_api_addr: String,
    pub local_zone: String,
    pub local_group_id: String,
    #[allow(dead_code)] // openraft 多节点加入时使用
    pub seed_peers: HashMap<u64, String>, // node_id → api_addr
}

impl ClusterConfig {
    /// 解析集群配置。若未设置 RUSTIO_CLUSTER_NODE_ID,返回单机模式(local_node_id=0)。
    pub(crate) fn parse() -> Self {
        let local_node_id = std::env::var("RUSTIO_CLUSTER_NODE_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let local_node_name = std::env::var("RUSTIO_CLUSTER_NODE_NAME")
            .unwrap_or_else(|_| format!("node-{local_node_id}"));
        let local_api_addr = std::env::var("RUSTIO_CLUSTER_NODE_ADDR")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
        let local_zone = std::env::var("RUSTIO_CLUSTER_NODE_ZONE")
            .unwrap_or_else(|_| "default".to_string());
        let local_group_id = std::env::var("RUSTIO_GROUP_ID")
            .unwrap_or_else(|_| "default".to_string());
        let seed_peers = parse_seed_peers();
        ClusterConfig { local_node_id, local_node_name, local_api_addr, local_zone, local_group_id, seed_peers }
    }

    /// 是否集群模式。
    pub(crate) fn is_cluster(&self) -> bool {
        self.local_node_id > 0
    }

    /// 生成本地磁盘的全局 ID。
    pub(crate) fn global_disk_id(&self, local_disk_index: usize) -> String {
        format!("{}-disk-{}", self.local_node_name, local_disk_index)
    }
}

/// 解析 RUSTIO_CLUSTER_SEEDS=1=http://n1:9000,2=http://n2:9000
fn parse_seed_peers() -> HashMap<u64, String> {
    let mut seeds = HashMap::new();
    let raw = std::env::var("RUSTIO_CLUSTER_SEEDS").unwrap_or_default();
    for item in raw.split(',') {
        let token = item.trim();
        if token.is_empty() {
            continue;
        }
        let mut pair = token.splitn(2, '=');
        let Some(id_str) = pair.next().map(str::trim).filter(|v| !v.is_empty()) else {
            continue;
        };
        let Some(addr) = pair.next().map(str::trim).filter(|v| !v.is_empty()) else {
            continue;
        };
        if let Ok(node_id) = id_str.parse::<u64>() {
            seeds.insert(node_id, addr.to_string());
        }
    }
    seeds
}
