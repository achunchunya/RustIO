#!/usr/bin/env bash
# RustIO 一键升级:从 GitHub Releases 下载最新版本并滚动重启集群。
#
# 用法:
#   curl -sSL https://raw.githubusercontent.com/achunchunya/RustIO/main/scripts/rolling-upgrade/upgrade.sh | bash
#   或:
#   bash upgrade.sh [--version v1.2.3] [--nodes nodes.conf] [--binary /usr/local/bin/rustio]
#
# 节点配置文件格式(每行): node_id  ssh_host  api_port  data_dir
#   meta-1  10.0.1.1  9000  /opt/rustio/data/meta-1
#   meta-2  10.0.1.2  9000  /opt/rustio/data/meta-2
#   meta-3  10.0.1.3  9000  /opt/rustio/data/meta-3
#
# 无节点配置文件时,升级本机 rustio 二进制(单节点模式)。
set -euo pipefail

REPO="achunchunya/RustIO"
GITHUB_API="https://api.github.com/repos/${REPO}"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download"
INSTALL_DIR="${RUSTIO_INSTALL_DIR:-/usr/local/bin}"
BINARY_PATH="${RUSTIO_BINARY:-${INSTALL_DIR}/rustio}"
NODE_CONFIG=""
TARGET_VERSION=""
UPGRADE_TIMEOUT="${UPGRADE_TIMEOUT:-120}"
UPGRADE_SETTLE="${UPGRADE_SETTLE:-10}"

# ── 参数解析 ──
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)   TARGET_VERSION="$2"; shift 2 ;;
    --nodes)     NODE_CONFIG="$2"; shift 2 ;;
    --binary)    BINARY_PATH="$2"; shift 2 ;;
    --help|-h)
      echo "用法: $0 [--version v1.2.3] [--nodes nodes.conf] [--binary /path/to/rustio]"
      echo ""
      echo "环境变量:"
      echo "  RUSTIO_INSTALL_DIR  安装目录(默认 /usr/local/bin)"
      echo "  RUSTIO_BINARY       二进制完整路径"
      echo "  UPGRADE_TIMEOUT     健康检查超时(秒,默认 120)"
      echo "  UPGRADE_SETTLE      Raft 追平等待(秒,默认 10)"
      exit 0
      ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

# ── 平台检测 ──
detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "${os}" in
    linux)  os="linux" ;;
    darwin) os="darwin" ;;
    *)      echo "❌ 不支持的操作系统: ${os}"; exit 1 ;;
  esac
  case "${arch}" in
    x86_64|amd64)  arch="amd64" ;;
    aarch64|arm64)  arch="arm64" ;;
    *)              echo "❌ 不支持的架构: ${arch}"; exit 1 ;;
  esac
  echo "rustio-${os}-${arch}"
}

# ── 版本查询 ──
get_latest_version() {
  curl -sSf "${GITHUB_API}/releases/latest" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null
}

get_current_version() {
  if [[ -x "${BINARY_PATH}" ]]; then
    "${BINARY_PATH}" --version 2>/dev/null | head -1 || echo "unknown"
  else
    echo "未安装"
  fi
}

# ── 下载 ──
download_binary() {
  local version="$1" asset="$2"
  local url="${DOWNLOAD_BASE}/${version}/${asset}.tar.gz"
  local tmp_dir
  tmp_dir=$(mktemp -d)

  echo "  下载 ${url}..." >&2
  if ! curl -sSfL "${url}" -o "${tmp_dir}/${asset}.tar.gz"; then
    echo "❌ 下载失败(版本 ${version} 可能不存在对应平台二进制)" >&2
    rm -rf "${tmp_dir}"
    return 1
  fi

  tar xzf "${tmp_dir}/${asset}.tar.gz" -C "${tmp_dir}"
  if [[ ! -f "${tmp_dir}/rustio" ]]; then
    echo "❌ 归档中未找到 rustio 二进制" >&2
    rm -rf "${tmp_dir}"
    return 1
  fi

  echo "${tmp_dir}/rustio"
}

# ── 节点操作 ──
SSH_USER="${SSH_USER:-root}"
SSH_KEY="${SSH_KEY:-}"
SSH_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
[[ -n "${SSH_KEY}" ]] && SSH_CMD="${SSH_CMD} -i ${SSH_KEY}"

is_local() {
  [[ "$1" == "127.0.0.1" || "$1" == "localhost" || "$1" == "0.0.0.0" ]]
}

wait_healthy() {
  local host="$1" port="$2"
  for _ in $(seq 1 "${UPGRADE_TIMEOUT}"); do
    curl -sf "http://${host}:${port}/health/ready" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

find_leader() {
  local -a hosts=("$@")
  for host_port in "${hosts[@]}"; do
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    local tk lid
    tk=$(curl -s -X POST "http://${host}:${port}/api/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d '{"username":"admin","password":"rustio-admin"}' 2>/dev/null \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('access_token',''))" 2>/dev/null)
    if [[ -n "${tk}" ]]; then
      lid=$(curl -s "http://${host}:${port}/api/v1/system/raft/status" \
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

upgrade_node() {
  local nid="$1" host="$2" port="$3" data_dir="$4" new_bin="$5"
  echo "  ── ${nid} (${host}:${port}) ──"

  # 停止
  if is_local "${host}"; then
    local pid
    pid=$(lsof -ti :"${port}" 2>/dev/null || true)
    [[ -n "${pid}" ]] && { kill "${pid}" 2>/dev/null || true; sleep 1; kill -9 "${pid}" 2>/dev/null || true; }
  else
    ${SSH_CMD} "${SSH_USER}@${host}" "pkill -f 'rustio.*server.*${data_dir}' 2>/dev/null; sleep 1; pkill -9 -f 'rustio.*server.*${data_dir}' 2>/dev/null" || true
  fi
  sleep 1

  # 部署二进制
  if is_local "${host}"; then
    cp "${new_bin}" "${BINARY_PATH}"
    chmod +x "${BINARY_PATH}"
  else
    scp -o StrictHostKeyChecking=no ${SSH_KEY:+-i ${SSH_KEY}} "${new_bin}" "${SSH_USER}@${host}:${BINARY_PATH}.new"
    ${SSH_CMD} "${SSH_USER}@${host}" "mv '${BINARY_PATH}.new' '${BINARY_PATH}' && chmod +x '${BINARY_PATH}'"
  fi

  # 启动
  if is_local "${host}"; then
    # 复用已有环境变量或 systemd
    if systemctl is-active rustio >/dev/null 2>&1; then
      systemctl restart rustio
    else
      nohup "${BINARY_PATH}" server "${data_dir}" --address ":${port}" >/dev/null 2>&1 &
    fi
  else
    ${SSH_CMD} "${SSH_USER}@${host}" "
      if systemctl is-active rustio >/dev/null 2>&1; then
        systemctl restart rustio
      else
        pkill -f '${BINARY_PATH}.*server' 2>/dev/null || true
        sleep 1
        nohup ${BINARY_PATH} server ${data_dir} --address :${port} >/dev/null 2>&1 &
      fi
    "
  fi

  # 等待健康
  echo "    等待健康..."
  if wait_healthy "${host}" "${port}"; then
    echo "    ✅ ${nid} 就绪"
  else
    echo "    ❌ ${nid} 健康检查超时"
    return 1
  fi
  sleep "${UPGRADE_SETTLE}"
  return 0
}

# ── 主流程 ──

echo "=== RustIO 一键升级 ==="

# 当前版本
CURRENT=$(get_current_version)
echo "  当前版本: ${CURRENT}"

# 目标版本
if [[ -z "${TARGET_VERSION}" ]]; then
  TARGET_VERSION=$(get_latest_version)
  if [[ -z "${TARGET_VERSION}" ]]; then
    echo "❌ 无法获取最新版本(检查网络或 GitHub API 限制)"
    exit 1
  fi
fi
echo "  目标版本: ${TARGET_VERSION}"

if [[ "${CURRENT}" == *"${TARGET_VERSION}"* ]]; then
  echo "  已是最新版本,无需升级"
  exit 0
fi

# 下载
PLATFORM=$(detect_platform)
echo "  平台: ${PLATFORM}"
NEW_BIN=$(download_binary "${TARGET_VERSION}" "${PLATFORM}")
echo "  ✅ 下载完成: ${NEW_BIN}"

# 升级模式
if [[ -n "${NODE_CONFIG}" && -f "${NODE_CONFIG}" ]]; then
  # ── 集群滚动升级 ──
  echo ""
  echo "=== 集群滚动升级 ==="

  declare -a NIDS=() NHOSTS=() NPORTS=() NDIRS=()
  while IFS= read -r line; do
    line=$(echo "${line}" | sed 's/#.*//' | xargs)
    [[ -z "${line}" ]] && continue
    read -r nid host port dir <<< "${line}"
    NIDS+=("${nid}")
    NHOSTS+=("${host}")
    NPORTS+=("${port}")
    NDIRS+=("${dir}")
  done < "${NODE_CONFIG}"

  echo "  节点数: ${#NIDS[@]}"

  # 找 leader
  LEADER=""
  for i in "${!NHOSTS[@]}"; do
    lid=$(find_leader "${NHOSTS[$i]}:${NPORTS[$i]}" || true)
    if [[ -n "${lid}" ]]; then LEADER="${lid}"; break; fi
  done
  echo "  当前 leader: ${LEADER:-未知}"

  # follower 先,leader 最后
  ORDER=()
  for i in "${!NIDS[@]}"; do
    [[ "${NIDS[$i]}" == "${LEADER}" ]] && continue
    ORDER+=($i)
  done
  for i in "${!NIDS[@]}"; do
    [[ "${NIDS[$i]}" == "${LEADER}" ]] && ORDER+=($i)
  done

  FAIL=0
  for i in "${ORDER[@]}"; do
    if ! upgrade_node "${NIDS[$i]}" "${NHOSTS[$i]}" "${NPORTS[$i]}" "${NDIRS[$i]}" "${NEW_BIN}"; then
      echo "❌ 升级 ${NIDS[$i]} 失败,中止"
      FAIL=1
      break
    fi
  done

  rm -f "${NEW_BIN}"

  if [[ "${FAIL}" -eq 0 ]]; then
    echo ""
    echo "=========================================="
    echo "  ✅ 集群升级完成 → ${TARGET_VERSION}"
    echo "=========================================="
  else
    exit 1
  fi
else
  # ── 单节点升级 ──
  echo ""
  echo "=== 单节点升级 ==="
  cp "${NEW_BIN}" "${BINARY_PATH}"
  chmod +x "${BINARY_PATH}"
  rm -f "${NEW_BIN}"

  if systemctl is-active rustio >/dev/null 2>&1; then
    echo "  重启 rustio 服务..."
    systemctl restart rustio
  else
    echo "  ⚠️  rustio 未作为 systemd 服务运行,请手动重启:"
    echo "     ${BINARY_PATH} server <data_dir> --address :9000"
  fi

  echo ""
  echo "=========================================="
  echo "  ✅ 升级完成 → ${TARGET_VERSION}"
  echo "=========================================="
fi
