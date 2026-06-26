#!/usr/bin/env bash
# 滚动升级：逐节点替换二进制并重启，集群始终维持 quorum 可用。
#
# 用法:
#   bash scripts/rolling-upgrade/rolling-upgrade.sh <新二进制路径> [节点配置文件]
#
# 节点配置文件格式(每行一个节点,空行和 # 跳过):
#   node_id  ssh_host  api_port  data_dir  [binary_path]
#   示例:
#     meta-1  10.0.1.1  9000  /opt/rustio/data/meta-1  /usr/local/bin/rustio
#     meta-2  10.0.1.2  9000  /opt/rustio/data/meta-2  /usr/local/bin/rustio
#     meta-3  10.0.1.3  9000  /opt/rustio/data/meta-3  /usr/local/bin/rustio
#
# 若不提供节点配置文件，默认本机 3 节点(端口 19801-19803, 用于开发/测试)。
#
# 可调环境变量:
#   UPGRADE_TIMEOUT    单节点健康检查超时(秒),默认 120
#   UPGRADE_SETTLE     节点就绪后等待 Raft 追平的额外时间(秒),默认 10
#   UPGRADE_DRY_RUN    1=只打印计划不执行
#   SSH_USER           SSH 用户名,默认 root
#   SSH_KEY            SSH 私钥路径(可选)
#   SSH_OPTS           额外 SSH 选项(可选)
set -euo pipefail

NEW_BINARY="${1:-}"
NODE_CONFIG="${2:-}"

if [[ -z "${NEW_BINARY}" ]]; then
  echo "用法: $0 <新二进制路径> [节点配置文件]"
  echo ""
  echo "节点配置文件格式(每行): node_id ssh_host api_port data_dir [binary_path]"
  exit 1
fi

if [[ ! -f "${NEW_BINARY}" ]]; then
  echo "❌ 新二进制不存在: ${NEW_BINARY}"
  exit 1
fi

TIMEOUT="${UPGRADE_TIMEOUT:-120}"
SETTLE="${UPGRADE_SETTLE:-10}"
DRY_RUN="${UPGRADE_DRY_RUN:-0}"
SSH_USER="${SSH_USER:-root}"
SSH_KEY="${SSH_KEY:-}"
SSH_OPTS="${SSH_OPTS:-}"

SSH_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
[[ -n "${SSH_KEY}" ]] && SSH_CMD="${SSH_CMD} -i ${SSH_KEY}"
[[ -n "${SSH_OPTS}" ]] && SSH_CMD="${SSH_CMD} ${SSH_OPTS}"

PASS=0; FAIL=0; ABORTED=0

ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

# ── 节点定义 ──
declare -a NODE_IDS=()
declare -a NODE_HOSTS=()
declare -a NODE_PORTS=()
declare -a NODE_DATADIRS=()
declare -a NODE_BINS=()

load_nodes() {
  if [[ -n "${NODE_CONFIG}" && -f "${NODE_CONFIG}" ]]; then
    while IFS= read -r line; do
      line=$(echo "${line}" | sed 's/#.*//' | xargs)
      [[ -z "${line}" ]] && continue
      read -r nid host port dir bin_extra <<< "${line}"
      NODE_IDS+=("${nid}")
      NODE_HOSTS+=("${host}")
      NODE_PORTS+=("${port}")
      NODE_DATADIRS+=("${dir}")
      NODE_BINS+=("${bin_extra:-rustio}")
    done < "${NODE_CONFIG}"
  else
    # 默认本机 3 节点(开发模式)
    echo "  未提供节点配置,使用本机 3 节点默认配置"
    for i in 1 2 3; do
      NODE_IDS+=("meta-${i}")
      NODE_HOSTS+=("127.0.0.1")
      NODE_PORTS+=("$((19800 + i))")
      NODE_DATADIRS+=("/tmp/rustio-upgrade-meta-${i}")
      NODE_BINS+=("rustio")
    done
  fi
}

# ── 节点操作 ──

# 等待节点健康
wait_healthy() {
  local host="$1" port="$2"
  for _ in $(seq 1 "${TIMEOUT}"); do
    if curl -sf "http://${host}:${port}/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# 检查 Raft 状态(返回 leader_id,空=无 leader)
get_raft_leader() {
  local host="$1" port="$2"
  local tk
  tk=$(curl -s -X POST "http://${host}:${port}/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"rustio-admin"}' 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('access_token',''))" 2>/dev/null)
  if [[ -n "${tk}" ]]; then
    curl -s "http://${host}:${port}/api/v1/system/raft/status" \
      -H "Authorization: Bearer ${tk}" 2>/dev/null \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('leader_id',''))" 2>/dev/null
  fi
}

# 获取 Raft commit_index
get_raft_commit_index() {
  local host="$1" port="$2"
  local tk
  tk=$(curl -s -X POST "http://${host}:${port}/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"rustio-admin"}' 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('access_token',''))" 2>/dev/null)
  if [[ -n "${tk}" ]]; then
    curl -s "http://${host}:${port}/api/v1/system/raft/status" \
      -H "Authorization: Bearer ${tk}" 2>/dev/null \
      -q 'null' \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('commit_index',0))" 2>/dev/null
  fi
}

# 等待集群有 leader
wait_cluster_leader() {
  for _ in $(seq 1 30); do
    for idx in "${!NODE_HOSTS[@]}"; do
      local lid
      lid=$(get_raft_leader "${NODE_HOSTS[$idx]}" "${NODE_PORTS[$idx]}" || true)
      if [[ -n "${lid}" && "${lid}" != "None" && "${lid}" != "null" ]]; then
        echo "${lid}"
        return 0
      fi
    done
    sleep 2
  done
  return 1
}

# 停止远程节点
stop_remote_node() {
  local host="$1" bin="$2"
  ${SSH_CMD} "${SSH_USER}@${host}" "pkill -f '${bin}' 2>/dev/null; sleep 1; pkill -9 -f '${bin}' 2>/dev/null" || true
}

# 替换远程二进制
deploy_binary() {
  local host="$1" remote_bin="$2"
  scp -o StrictHostKeyChecking=no ${SSH_KEY:+-i ${SSH_KEY}} "${NEW_BINARY}" "${SSH_USER}@${host}:${remote_bin}.new"
  ${SSH_CMD} "${SSH_USER}@${host}" "mv '${remote_bin}.new' '${remote_bin}' && chmod +x '${remote_bin}'"
}

# 启动远程节点
start_remote_node() {
  local host="$1" bin="$2" dir="$3" node_id="$4" port="$5"
  # 构建环境变量(假设 systemd 管理或直接 nohup)
  ${SSH_CMD} "${SSH_USER}@${host}" "nohup ${bin} server ${dir} --address :${port} >/dev/null 2>&1 &"
}

# ── 本地模式操作 ──

stop_local_node() {
  local port="$1"
  local pid
  pid=$(lsof -ti :"${port}" 2>/dev/null || true)
  if [[ -n "${pid}" ]]; then
    kill "${pid}" 2>/dev/null || true
    sleep 1
    kill -9 "${pid}" 2>/dev/null || true
  fi
}

deploy_local_binary() {
  local target_bin="$1"
  cp "${NEW_BINARY}" "${target_bin}"
  chmod +x "${target_bin}"
}

start_local_node() {
  local dir="$1" port="$2" bin="$3"
  mkdir -p "${dir}"
  nohup "${bin}" server "${dir}" --address ":${port}" >/dev/null 2>&1 &
}

# ── 主逻辑 ──

is_local_node() {
  local host="$1"
  [[ "${host}" == "127.0.0.1" || "${host}" == "localhost" || "${host}" == "0.0.0.0" ]]
}

upgrade_one_node() {
  local idx="$1"
  local nid="${NODE_IDS[$idx]}"
  local host="${NODE_HOSTS[$idx]}"
  local port="${NODE_PORTS[$idx]}"
  local dir="${NODE_DATADIRS[$idx]}"
  local bin="${NODE_BINS[$idx]}"

  echo ""
  echo "  ── 升级 ${nid} (${host}:${port}) ──"

  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "  [DRY-RUN] 跳过实际执行"
    return 0
  fi

  # 1) 停止节点
  echo "  停止 ${nid}..."
  if is_local_node "${host}"; then
    stop_local_node "${port}"
  else
    stop_remote_node "${host}" "${bin}"
  fi
  sleep 2

  # 2) 替换二进制
  echo "  部署新二进制..."
  if is_local_node "${host}"; then
    deploy_local_binary "${bin}"
  else
    deploy_binary "${host}" "${bin}"
  fi

  # 3) 启动节点
  echo "  启动 ${nid}..."
  if is_local_node "${host}"; then
    start_local_node "${dir}" "${port}" "${bin}"
  else
    start_remote_node "${host}" "${bin}" "${dir}" "${nid}" "${port}"
  fi

  # 4) 等待健康
  echo "  等待健康检查..."
  if ! wait_healthy "${host}" "${port}"; then
    bad "${nid} 健康检查超时(${TIMEOUT}s)"
    return 1
  fi
  ok "${nid} 健康检查通过"

  # 5) 等待 Raft 追平
  echo "  等待 Raft 追平(${SETTLE}s)..."
  sleep "${SETTLE}"

  # 6) 验证集群 leader 存在
  local lid
  lid=$(wait_cluster_leader || true)
  if [[ -z "${lid}" ]]; then
    bad "升级 ${nid} 后集群无 leader"
    return 1
  fi
  ok "集群 leader: ${lid}"

  return 0
}

# ── 主流程 ──

echo "=== RustIO 滚动升级 ==="
echo "  新二进制: ${NEW_BINARY}"
echo "  超时: ${TIMEOUT}s"
echo "  追平等待: ${SETTLE}s"
[[ "${DRY_RUN}" == "1" ]] && echo "  ⚠️  DRY-RUN 模式"

load_nodes

echo ""
echo "  节点数: ${#NODE_IDS[@]}"
for idx in "${!NODE_IDS[@]}"; do
  echo "    ${NODE_IDS[$idx]} → ${NODE_HOSTS[$idx]}:${NODE_PORTS[$idx]}"
done

# 预检:所有节点当前可达
echo ""
echo "=== 预检:集群当前状态 ==="
ALL_REACHABLE=true
for idx in "${!NODE_HOSTS[@]}"; do
  if wait_healthy "${NODE_HOSTS[$idx]}" "${NODE_PORTS[$idx]}" 2>/dev/null; then
    ok "${NODE_IDS[$idx]} 可达"
  else
    bad "${NODE_IDS[$idx]} 不可达"
    ALL_REACHABLE=false
  fi
done

if [[ "${ALL_REACHABLE}" == "false" ]]; then
  echo "❌ 部分节点不可达,中止升级"
  exit 1
fi

LEADER=$(wait_cluster_leader || true)
echo "  当前 leader: ${LEADER:-未知}"

# 滚动升级:follower 先升级,leader 最后
echo ""
echo "=== 开始滚动升级 ==="

# 排序:非 leader 节点先升级,leader 最后
UPGRADE_ORDER=()
LEADER_IDX=-1
for idx in "${!NODE_IDS[@]}"; do
  if [[ "meta-${NODE_IDS[$idx]}" == "${LEADER}" || "${NODE_IDS[$idx]}" == "${LEADER}" ]]; then
    LEADER_IDX=$idx
  else
    UPGRADE_ORDER+=($idx)
  fi
done
[[ ${LEADER_IDX} -ge 0 ]] && UPGRADE_ORDER+=(${LEADER_IDX})

TOTAL=${#UPGRADE_ORDER[@]}
CURRENT=0

for idx in "${UPGRADE_ORDER[@]}"; do
  CURRENT=$((CURRENT + 1))
  echo ""
  echo "=== [${CURRENT}/${TOTAL}] 升级 ${NODE_IDS[$idx]} ==="
  if ! upgrade_one_node "${idx}"; then
    echo ""
    echo "❌ 升级 ${NODE_IDS[$idx]} 失败,中止后续升级"
    ABORTED=1
    break
  fi
done

# ── 最终验证 ──
echo ""
echo "=== 最终验证 ==="
if [[ "${DRY_RUN}" != "1" && "${ABORTED}" == "0" ]]; then
  sleep 5
  FINAL_LEADER=$(wait_cluster_leader || true)
  if [[ -n "${FINAL_LEADER}" ]]; then
    ok "集群 leader: ${FINAL_LEADER}"
  else
    bad "集群无 leader"
  fi

  # 验证所有节点可达
  for idx in "${!NODE_HOSTS[@]}"; do
    if wait_healthy "${NODE_HOSTS[$idx]}" "${NODE_PORTS[$idx]}" 2>/dev/null; then
      ok "${NODE_IDS[$idx]} 升级后可达"
    else
      bad "${NODE_IDS[$idx]} 升级后不可达"
    fi
  done
fi

# ── 汇总 ──
echo ""
echo "=========================================="
echo "  滚动升级完成: 通过 ${PASS} / 失败 ${FAIL}"
if [[ "${ABORTED}" == "1" ]]; then
  echo "  ⚠️  升级中止,部分节点可能仍在运行旧版本"
fi
echo "=========================================="
exit ${FAIL}
