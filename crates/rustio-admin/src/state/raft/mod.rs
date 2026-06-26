//! openraft 0.9 集成:TypeConfig + 命令 + redb log storage + state machine + HTTP network。
//!
//! NodeId 用 u64(openraft 要求 Copy,String 不行);peer 的 "meta-1" 地址塞进 BasicNode。

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Arc, OnceLock, Weak};

use openraft::{BasicNode, Config, TokioRuntime};

use crate::state::AppState;

pub(crate) mod command;
pub(crate) mod log_store;
pub(crate) mod network;
pub(crate) mod state_machine;

pub(crate) use command::{CommandResponse, MetadataCommand};

openraft::declare_raft_types!(
    pub(crate) TypeConfig:
        D = MetadataCommand,
        R = CommandResponse,
        NodeId = u64,
        Node = BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = TokioRuntime,
);

pub(crate) type MetadataRaft = openraft::Raft<TypeConfig>;

/// AppState 弱引用 holder:state machine 经它访问 AppState 字段做 apply。
/// `Weak` 打破 AppState ⇄ Raft ⇄ StateMachine 循环;构造 raft 时传入空 holder,
/// AppState `Arc::new` 后回填 `Arc::downgrade(&state)`。
pub(crate) type AppStateRef = Arc<OnceLock<Weak<AppState>>>;

/// 启动 metadata raft(单节点或集群模式)。
///
/// - 集群模式:解析 `RUSTIO_METADATA_RAFT_PEERS` 或从 `cluster_peers` 构建成员集,
///   先 `initialize` 单节点,再 `add_learner` + `change_membership` 扩展为多节点。
/// - 单节点模式:peer 列表为空或仅自身,仅 `initialize` 单成员集。
/// - 幂等:已初始化(`meta_raft` 非空)直接返回。
async fn start_raft(
    node_id: u64,
    db: Arc<redb::Database>,
    app: AppStateRef,
    peer_api_addrs: std::collections::HashMap<u64, String>,
    internal_token: String,
    members: BTreeMap<u64, BasicNode>,
    should_initialize: bool,
) -> Result<MetadataRaft, String> {
    let config = Arc::new(
        Config {
            cluster_name: "rustio-meta".into(),
            election_timeout_min: 300,
            election_timeout_max: 600,
            heartbeat_interval: 100,
            ..Default::default()
        }
        .validate()
        .map_err(|err| err.to_string())?,
    );
    let log_store = log_store::RedbLogStore::new(db.clone()).map_err(|err| format!("{err:?}"))?;
    let state_machine = state_machine::RedbStateMachine::new(app, db).map_err(|err| format!("{err:?}"))?;
    let network = network::NetworkFactory::new(peer_api_addrs, internal_token);
    let raft = openraft::Raft::new(node_id, config, network, log_store, state_machine)
        .await
        .map_err(|err| format!("{err:?}"))?;

    // 仅 bootstrap 节点(集群最小 node_id;单机即自身)执行 initialize,写入初始成员集;
    // 其余节点不 initialize,启动引擎后等待 leader 经 append_entries 复制 membership。
    // 这避免「每节点各自 initialize 单 voter」造成的多 leader 脑裂。
    if should_initialize {
        if let Err(err) = raft.initialize(members).await {
            // 重启后已初始化返回 NotAllowed,属正常幂等;其余情况记日志但不阻断启动。
            tracing::warn!(node_id, "metadata raft initialize: {err:?}");
        }
    }

    Ok(raft)
}

impl AppState {
    /// 提交元数据变更命令。集群模式经 openraft `client_write` 复制 + apply;
    /// 单机未启 raft(`meta_raft` 空)时直接本地 apply,保证单机/小集群可用。
    /// follower 收到写时 openraft 返回 ForwardToLeader,转发到 leader 内部写端点。
    pub(crate) async fn submit_metadata_command(&self, cmd: MetadataCommand) -> Result<(), String> {
        let Some(raft) = self.meta_raft.get() else {
            cmd.apply(self).await;
            return Ok(());
        };
        match raft.client_write(cmd.clone()).await {
            Ok(_) => Ok(()),
            Err(err) => {
                // 非 leader:openraft 返回 ForwardToLeader,取 leader 地址转发其内部写端点。
                if let Some(forward) = err.forward_to_leader() {
                    let leader_addr = forward
                        .leader_node
                        .as_ref()
                        .map(|node| node.addr.clone())
                        .filter(|addr| !addr.is_empty());
                    if let Some(addr) = leader_addr {
                        return self.forward_metadata_command_to_leader(&addr, &cmd).await;
                    }
                    return Err(format!(
                        "metadata raft 写需转发 leader,但 leader 地址未知: {err:?}"
                    ));
                }
                Err(format!("metadata raft 提交失败: {err:?}"))
            }
        }
    }

    /// 把命令 RPC 转发到 leader 的内部写端点(含一次重试)。
    async fn forward_metadata_command_to_leader(
        &self,
        leader_addr: &str,
        cmd: &MetadataCommand,
    ) -> Result<(), String> {
        let url = format!("{leader_addr}/api/v1/internal/metadata-raft/write");
        let token = AppState::internal_control_token();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|err| format!("构建转发 client 失败: {err}"))?;
        let mut last_err = String::new();
        for attempt in 0..2 {
            match client
                .post(&url)
                .header("x-rustio-internal-token", &token)
                .json(cmd)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    last_err = format!("leader 转发返回 HTTP {}", resp.status());
                }
                Err(err) => {
                    last_err = format!("leader 转发请求失败: {err}");
                }
            }
            if attempt == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
        Err(format!("metadata raft 写转发 leader 失败: {last_err}"))
    }

    /// 动态成员变更:把新节点加入 raft 集群(本节点须是 leader)。
    ///
    /// 流程:add_learner(追日志) → change_membership(提升为 voter) → UpsertClusterPeer(复制拓扑)。
    /// 加节点是 leader-only 操作;非 leader 调用返回错误(调用方负责判 leader 或转发)。
    pub(crate) async fn raft_add_member(
        &self,
        peer: crate::state::cluster::ClusterPeerInfo,
    ) -> Result<(), String> {
        let Some(raft) = self.meta_raft.get() else {
            return Err("metadata raft 未初始化(单机模式不支持动态成员)".to_string());
        };
        let node_id = peer.node_id;
        let node = openraft::BasicNode::new(peer.api_addr.clone());

        // 1) add_learner:新节点作为 learner 加入并追平日志(blocking=true 等待追上)。
        raft.add_learner(node_id, node, true)
            .await
            .map_err(|err| format!("add_learner({node_id}) 失败: {err:?}"))?;

        // 2) change_membership:把现有 voter 集 + 新节点一起作为新 voter 集提交(retain 保留)。
        let mut voters: std::collections::BTreeSet<u64> = {
            let metrics = raft.metrics();
            let m = metrics.borrow();
            m.membership_config.voter_ids().collect()
        };
        voters.insert(node_id);
        raft.change_membership(voters, true)
            .await
            .map_err(|err| format!("change_membership(add {node_id}) 失败: {err:?}"))?;

        // 3) 把新节点拓扑经 raft 复制到各节点 cluster_peers(全集群一致,EC 放置纳入新节点)。
        self.submit_metadata_command(MetadataCommand::UpsertClusterPeer(Box::new(peer)))
            .await?;
        Ok(())
    }

    /// 动态成员变更:把节点从 raft 集群移除(本节点须是 leader)。
    ///
    /// 流程:change_membership(voters−{node_id}) 收缩 voter 集 → RemoveClusterPeer(复制拓扑收缩)。
    /// 移除是 leader-only 操作;非 leader 调用返回错误(调用方负责判 leader 或转发)。
    /// 不允许移除 leader 自身(避免成员变更与让位交错的不确定态;先由其他节点接任再移)。
    pub(crate) async fn raft_remove_member(&self, node_id: u64) -> Result<(), String> {
        let Some(raft) = self.meta_raft.get() else {
            return Err("metadata raft 未初始化(单机模式不支持动态成员)".to_string());
        };
        if node_id == self.local_node_id {
            return Err("不允许移除 leader 自身;请在其他节点发起移除".to_string());
        }

        let mut voters: std::collections::BTreeSet<u64> = {
            let metrics = raft.metrics();
            let m = metrics.borrow();
            m.membership_config.voter_ids().collect()
        };
        let was_voter = voters.remove(&node_id);
        if voters.is_empty() {
            return Err("移除后将无任何 voter,拒绝执行".to_string());
        }

        // 1) change_membership:以收缩后的 voter 集提交(retain=false 同时移出 learner 残留)。
        //    目标本就不是 voter(如仅 learner/拓扑残留)时跳过,直接清理拓扑。
        if was_voter {
            raft.change_membership(voters, false)
                .await
                .map_err(|err| format!("change_membership(remove {node_id}) 失败: {err:?}"))?;
        }

        // 2) 把拓扑收缩经 raft 复制到各节点 cluster_peers(EC 放置/布局自动排除该节点)。
        self.submit_metadata_command(MetadataCommand::RemoveClusterPeer { node_id })
            .await?;
        Ok(())
    }

    /// 本节点是否为 metadata raft 的 leader。
    pub(crate) fn is_metadata_leader(&self) -> bool {
        if let Some(raft) = self.meta_raft.get() {
            let metrics = raft.metrics();
            let m = metrics.borrow();
            m.current_leader == Some(self.local_node_id)
        } else {
            false
        }
    }

    /// 返回当前 leader 的 api_addr(若已知),用于把 leader-only 操作转发到 leader。
    pub(crate) fn metadata_leader_addr(&self) -> Option<String> {
        let raft = self.meta_raft.get()?;
        let metrics = raft.metrics();
        let m = metrics.borrow();
        let leader_id = m.current_leader?;
        let addr = m
            .membership_config
            .nodes()
            .find(|(id, _)| **id == leader_id)
            .map(|(_, node)| node.addr.clone());
        drop(m);
        addr.filter(|addr| !addr.is_empty())
    }

    /// Graceful leader transfer:当前 leader 主动让位给指定目标节点。
    ///
    /// 流程:
    /// 1. 停止发送 heartbeat → follower 检测到超时
    /// 2. HTTP RPC 触发目标节点立即发起 election
    /// 3. 等待目标节点赢得选举(≤5s)
    /// 4. 恢复 heartbeat
    pub(crate) async fn raft_transfer_leader(
        &self,
        target_node_id: u64,
    ) -> Result<(), String> {
        let raft = self
            .meta_raft
            .get()
            .ok_or_else(|| "metadata raft 未初始化".to_string())?;

        // 必须在 leader 上发起 transfer
        if !self.is_metadata_leader() {
            return Err("仅 leader 可发起 transfer;请在 leader 节点调用".to_string());
        }
        if target_node_id == self.local_node_id {
            return Err("目标节点已是 leader,无需转移".to_string());
        }

        // 查找目标节点地址
        let target_addr = {
            let metrics = raft.metrics();
            let m = metrics.borrow();
            let mut found = None;
            for (id, node) in m.membership_config.nodes() {
                if *id == target_node_id && !node.addr.is_empty() {
                    found = Some(node.addr.clone());
                    break;
                }
            }
            found.ok_or_else(|| format!("目标节点 {target_node_id} 不在集群成员中"))?
        };

        // 1) 停止发送 heartbeat → follower election_timeout 后自动超时
        raft.runtime_config().heartbeat(false);

        // 2) HTTP RPC 触发目标节点立即发起 election
        let token = Self::internal_control_token();
        let url = format!("{target_addr}/api/v1/internal/metadata-raft/trigger-elect");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .map_err(|err| format!("构建 HTTP client 失败: {err}"))?;

        let send_result = client
            .post(&url)
            .header("x-rustio-internal-token", &token)
            .send()
            .await;
        // 即使 RPC 失败也继续 — follower 超时后仍会自行触发 election
        if let Err(err) = send_result {
            eprintln!("  [raft] trigger-elect RPC 失败(将依赖超时): {err}");
        }

        // 3) 等待目标节点成为 leader(最长 5s)
        let mut target_is_leader = false;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let metrics = raft.metrics();
            let m = metrics.borrow();
            if m.current_leader == Some(target_node_id) {
                target_is_leader = true;
                break;
            }
        }

        // 4) 恢复 heartbeat(无论成功与否)
        raft.runtime_config().heartbeat(true);

        if !target_is_leader {
            return Err(format!(
                "leader 转移超时:目标节点 {target_node_id} 未在 5s 内成为 leader"
            ));
        }

        Ok(())
    }

    /// 启动元数据 raft(集群检测:有已知 peer 则多节点初始化)。
    /// async 上下文(server 启动)调用一次,幂等。
    pub async fn init_metadata_raft(self: &Arc<Self>, node_id: u64) -> Result<(), String> {
        if self.meta_raft.get().is_some() {
            return Ok(());
        }
        let db_path = self.data_dir.join(".rustio_meta_raft.redb");
        let db = Arc::new(
            redb::Database::create(&db_path).map_err(|err| format!("打开 raft redb 失败: {err}"))?,
        );

        // 构建 peer API 地址映射:优先从 cluster_peers，回退 metadata_peer_endpoints
        let mut peer_api_addrs = std::collections::HashMap::new();
        let cluster_peers = self.cluster_peers.read().await;
        if !cluster_peers.is_empty() {
            for (&id, info) in cluster_peers.iter() {
                peer_api_addrs.insert(id, info.api_addr.clone());
            }
        }
        // 补充 seed peers(解析 RUSTIO_CLUSTER_SEEDS)
        let config = crate::state::cluster::ClusterConfig::parse();
        for (seed_id, seed_addr) in &config.seed_peers {
            peer_api_addrs.entry(*seed_id).or_insert_with(|| seed_addr.clone());
        }
        drop(cluster_peers);

        // 构建初始成员集与 bootstrap 决策。
        // 「初始成员」判据 = 本节点在配置的 seed_peers 中(env RUSTIO_CLUSTER_SEEDS 含自己)。
        //   - 初始成员:进入初始 voter 集;仅最小 node_id 执行 initialize,其余等待复制 membership。
        //   - 新节点(seed 不含自己):不进初始 voter 集、不 initialize,启动后自动 join 被 leader 纳入。
        // 注意:不能用 cluster_peers 判断,因 bootstrap 会把自己填入 cluster_peers。
        let is_cluster = self.local_node_id > 0;
        let is_seed_member = !is_cluster || config.seed_peers.contains_key(&self.local_node_id);
        let mut members: BTreeMap<u64, BasicNode> = BTreeMap::new();
        if is_cluster {
            // 初始 voter 集 = 全部 seed 成员(含自己当且仅当自己是 seed)。
            for (&id, addr) in &peer_api_addrs {
                if config.seed_peers.contains_key(&id) || id == self.local_node_id && is_seed_member
                {
                    members.insert(id, BasicNode::new(addr.clone()));
                }
            }
            // 兜底:若自己是 seed 但因某种原因未在 peer_api_addrs,补进。
            if is_seed_member {
                members
                    .entry(self.local_node_id)
                    .or_insert_with(|| BasicNode::new(config.local_api_addr.clone()));
            }
        } else {
            members.insert(node_id, BasicNode::new(String::new()));
        }
        // 新节点(非 seed 成员)初始 members 为空集——它不 initialize,纯等待被纳入。
        let min_voter = members.keys().next().copied();
        let should_initialize =
            !is_cluster || (is_seed_member && Some(node_id) == min_voter);

        let internal_token = AppState::internal_control_token();
        let raft = start_raft(
            node_id,
            db,
            self.meta_raft_app.clone(),
            peer_api_addrs,
            internal_token,
            members,
            should_initialize,
        )
        .await?;
        let _ = self.meta_raft_app.set(Arc::downgrade(self));
        let _ = self.meta_raft.set(raft);

        // 新节点自动 join:集群模式下,本节点不是 seed 成员(env SEEDS 不含自己)→ 是后加入的新节点,
        // 向某个 seed 发 join 请求,由 seed(或转发到 leader)纳入。
        if is_cluster && !is_seed_member {
            let seeds: Vec<String> = config.seed_peers.values().cloned().collect();
            tracing::info!(node_id = self.local_node_id, seed_count = seeds.len(), "新节点启动,发起自动 join");
            self.spawn_auto_join(config.local_api_addr.clone(), config.local_node_name.clone(), seeds);
        }
        Ok(())
    }

    /// 后台尝试向 seed 节点发起 join(新节点自动加入)。非阻塞:启动不因 join 失败而失败,
    /// leader 暂不可达时重试若干次。
    fn spawn_auto_join(
        self: &Arc<Self>,
        local_api_addr: String,
        local_node_name: String,
        seeds: Vec<String>,
    ) {
        if seeds.is_empty() {
            return;
        }
        let state = Arc::clone(self);
        tokio::spawn(async move {
            // 构造本节点拓扑(含真实磁盘列表,去同构假设)。
            let disks: Vec<crate::state::cluster::ClusterDiskInfo> = {
                let peers = state.cluster_peers.read().await;
                peers
                    .get(&state.local_node_id)
                    .map(|info| info.disks.clone())
                    .unwrap_or_default()
            };
            let peer = crate::state::cluster::ClusterPeerInfo {
                node_id: state.local_node_id,
                node_name: local_node_name,
                api_addr: local_api_addr,
                zone: "default".to_string(),
                disks,
                draining: false,
            };
            let token = AppState::internal_control_token();
            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
            {
                Ok(c) => c,
                Err(err) => {
                    tracing::warn!("自动 join 构建 client 失败: {err}");
                    return;
                }
            };
            // 给集群一点选主时间,然后重试向各 seed 发 join(seed 非 leader 会自身转发到 leader)。
            for attempt in 0..10u32 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                for seed in &seeds {
                    let url = format!("{seed}/api/v1/internal/cluster/membership/add");
                    match client
                        .post(&url)
                        .header("x-rustio-internal-token", &token)
                        .json(&peer)
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            tracing::info!(node_id = state.local_node_id, seed = %seed, "新节点自动 join 成功");
                            return;
                        }
                        Ok(resp) => {
                            tracing::debug!(seed = %seed, status = %resp.status(), "自动 join 暂未成功(可能 seed 非 leader/选主中)");
                        }
                        Err(err) => {
                            tracing::debug!(seed = %seed, error = %err, "自动 join 请求失败,重试");
                        }
                    }
                }
                let _ = attempt;
            }
            tracing::warn!(node_id = state.local_node_id, "新节点自动 join 多次重试仍失败,请检查 seed/网络或改用管理员显式加节点");
        });
    }
}

