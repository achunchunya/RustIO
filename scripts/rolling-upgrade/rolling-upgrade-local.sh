#!/usr/bin/env bash
# 本机滚动升级(开发/测试):更新二进制后逐节点重启本地集群。
#
# 用法:
#   bash scripts/rolling-upgrade/rolling-upgrade-local.sh <新二进制路径> [端口1 端口2 端口3]
#
# 默认端口 19801-19803,数据目录 /tmp/rustio-upgrade-meta-{1,2,3}。
set -euo pipefail

NEW_BINARY="${1:-}"
shift 2>/dev/null || true
PORTS=("${@:-19801 19802 19803}")
[[ ${#PORTS[@]} -eq 0 ]] && PORTS=(19801 19802 19803)

if [[ -z "${NEW_BINARY}" ]]; then
  echo "用法: $0 <新二进制路径> [端口1 端口2 端口3]"
  exit 1
fi

if [[ ! -f "${NEW_BINARY}" ]]; then
  echo "❌ 新二进制不存在: ${NEW_BINARY}"
  exit 1
fi

TIMEOUT="${UPGRADE_TIMEOUT:-60}"
SETTLE="${UPGRADE_SETTLE:-5}"
INTERNAL_TOKEN="rolling-upgrade-token"
DATA_ROOT="${TMPDIR:-/tmp}/rustio-upgrade"
PASS=0; FAIL=0

ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

wait_ready() {
  local port="$1"
  for _ in $(seq 1 "${TIMEOUT}"); do
    curl -sf "http://127.0.0.1:${port}/health/ready" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

find_leader() {
  for p in "${PORTS[@]}"; do
    local tk lid
    tk=$(curl -s -X POST "http://127.0.0.1:${p}/api/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d '{"username":"admin","password":"rustio-admin"}' 2>/dev/null \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('access_token',''))" 2>/dev/null)
    if [[ -n "${tk}" ]]; then
      lid=$(curl -s "http://127.0.0.1:${p}/api/v1/system/raft/status" \
        -H "Authorization: Bearer ${tk}" 2>/dev/null \
        | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('leader_id',''))" 2>/dev/null)
      if [[ -n "${lid}" && "${lid}" != "None" && "${lid}" != "null" ]]; then
        echo "${lid}"
        return 0
      fi
    fi
  done
  return 1
}

stop_port() {
  local port="$1"
  local pid
  pid=$(lsof -ti :"${port}" 2>/dev/null || true)
  if [[ -n "${pid}" ]]; then
    kill "${pid}" 2>/dev/null || true
    sleep 1
    kill -9 "${pid}" 2>/dev/null || true
  fi
}

start_node() {
  local port="$1" data_dir="$2"
  local node_id="meta-$(( port - 19800 ))"
  local peer_map=""
  for p in "${PORTS[@]}"; do
    local pn="meta-$(( p - 19800 ))"
    [[ -n "${peer_map}" ]] && peer_map="${peer_map},"
    peer_map="${peer_map}${pn}=http://127.0.0.1:${p}"
  done
  mkdir -p "${data_dir}"
  RUSTIO_DATA_DIR="${data_dir}" \
  RUSTIO_ADDR=":${port}" \
  RUSTIO_ROOT_USER="rustioadmin" \
  RUSTIO_ROOT_PASSWORD="rustioadmin" \
  RUSTIO_CONSOLE_USER="admin" \
  RUSTIO_CONSOLE_PASSWORD="rustio-admin" \
  RUSTIO_INTERNAL_TOKEN="${INTERNAL_TOKEN}" \
  RUSTIO_METADATA_RAFT_NODE_ID="${node_id}" \
  RUSTIO_METADATA_RAFT_NETWORK_ENABLED="true" \
  RUSTIO_METADATA_RAFT_NETWORK_STRICT="true" \
  RUSTIO_METADATA_RAFT_PEERS="${peer_map}" \
  RUST_LOG=error \
    nohup "${NEW_BINARY}" server "${data_dir}" --address ":${port}" >/dev/null 2>&1 &
}

# ── 主流程 ──

echo "=== RustIO 本机滚动升级 ==="
echo "  新二进制: ${NEW_BINARY}"
echo "  端口: ${PORTS[*]}"
echo ""

# 预检
echo "=== 预检 ==="
ALL_OK=true
for port in "${PORTS[@]}"; do
  if curl -sf "http://127.0.0.1:${port}/health/ready" >/dev/null 2>&1; then
    ok "端口 ${port} 可达"
  else
    echo "  ⚠️  端口 ${port} 不可达(可能未启动)"
    ALL_OK=false
  fi
done

LEADER=""
if [[ "${ALL_OK}" == "true" ]]; then
  LEADER=$(find_leader || true)
  echo "  当前 leader: ${LEADER:-未知}"
fi

# 排序:非 leader 先升级
declare -a ORDER=()
LEADER_PORT=""
if [[ -n "${LEADER}" ]]; then
  LEADER_PORT=$(python3 -c "
m = {'meta-1': 19801, 'meta-2': 19802, 'meta-3': 19803}
print(m.get('${LEADER}', ''))
" 2>/dev/null || true)
fi

for port in "${PORTS[@]}"; do
  if [[ "${port}" != "${LEADER_PORT}" ]]; then
    ORDER+=("${port}")
  fi
done
[[ -n "${LEADER_PORT}" ]] && ORDER+=("${LEADER_PORT}")

# 滚动升级
echo ""
echo "=== 滚动升级 ==="
TOTAL=${#ORDER[@]}
for i in "${!ORDER[@]}"; do
  port="${ORDER[$i]}"
  idx=$((i + 1))
  data_dir="${DATA_ROOT}/meta-$(( port - 19800 ))"
  node_id="meta-$(( port - 19800 ))"

  echo ""
  echo "  [${idx}/${TOTAL}] 升级 ${node_id} (端口 ${port})"

  # 停止
  echo "    停止..."
  stop_port "${port}"

  # 启动(二进制已替换)
  echo "    启动..."
  start_node "${port}" "${data_dir}"

  # 等待健康
  echo "    等待健康..."
  if wait_ready "${port}"; then
    ok "${node_id} 健康"
  else
    bad "${node_id} 健康检查超时"
    echo "❌ 中止升级"
    exit 1
  fi

  # 等待追平
  echo "    等待 Raft 追平(${SETTLE}s)..."
  sleep "${SETTLE}"

  # 验证 leader
  NEW_LEADER=$(find_leader || true)
  if [[ -n "${NEW_LEADER}" ]]; then
    ok "集群 leader: ${NEW_LEADER}"
  else
    bad "集群无 leader"
  fi
done

# 最终验证
echo ""
echo "=== 最终验证 ==="
sleep 3
FINAL_LEADER=$(find_leader || true)
if [[ -n "${FINAL_LEADER}" ]]; then
  ok "集群 leader: ${FINAL_LEADER}"
else
  bad "集群无 leader"
fi

for port in "${PORTS[@]}"; do
  if curl -sf "http://127.0.0.1:${port}/health/ready" >/dev/null 2>&1; then
    ok "端口 ${port} 可达"
  else
    bad "端口 ${port} 不可达"
  fi
done

echo ""
echo "=========================================="
echo "  滚动升级完成: 通过 ${PASS} / 失败 ${FAIL}"
echo "=========================================="
exit ${FAIL}
