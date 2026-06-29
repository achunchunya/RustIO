#!/usr/bin/env bash
# RustIO 一键部署 3 节点集群(单机开发/测试模式)。
#
# 用法:
#   curl -sSL https://raw.githubusercontent.com/achunchunya/RustIO/main/scripts/deploy/install-cluster.sh | bash
#   或:
#   bash install-cluster.sh [--version v0.1.0]
#
# 等同于运行 3 个 RustIO 实例,组成 Raft 集群。
set -euo pipefail

REPO="achunchunya/RustIO"
GITHUB_API="https://api.github.com/repos/${REPO}"
INSTALL_DIR="${RUSTIO_INSTALL_DIR:-/usr/local/bin}"
BINARY="${INSTALL_DIR}/rustio"
VERSION="${RUSTIO_VERSION:-}"
BASE_PORT="${RUSTIO_BASE_PORT:-19801}"
DATA_ROOT="${RUSTIO_DATA_ROOT:-/opt/rustio/cluster}"
INTERNAL_TOKEN="rustio-cluster-$(date +%s)"
ROOT_PASS="${RUSTIO_ROOT_PASS:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --port)    BASE_PORT="$2"; shift 2 ;;
    --data)    DATA_ROOT="$2"; shift 2 ;;
    --help|-h) echo "用法: $0 [--version v0.1.0] [--port 19801] [--data /opt/rustio/cluster]"; exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

# ── 检查是否已安装 ──
if [[ ! -x "${BINARY}" ]]; then
  echo "  RustIO 未安装,先执行单节点部署..."
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  INSTALL_ARGS=""
  [[ -n "${VERSION}" ]] && INSTALL_ARGS="${INSTALL_ARGS} --version ${VERSION}"
  INSTALL_ARGS="${INSTALL_ARGS} --port ${BASE_PORT} --data ${DATA_ROOT}/meta-1"
  INSTALL_ARGS="${INSTALL_ARGS} --user root"
  bash "${SCRIPT_DIR}/install.sh" ${INSTALL_ARGS} --version "${VERSION:-latest}" 2>/dev/null || true
  # 获取安装脚本生成的密码
  ROOT_PASS=$(grep RUSTIO_ROOT_PASSWORD /etc/rustio/env 2>/dev/null | cut -d= -f2 || echo "")
fi

[[ -z "${ROOT_PASS}" ]] && ROOT_PASS=$(python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)))" 2>/dev/null || echo "rustio-cluster-pass")

echo ""
echo "=== 部署 3 节点集群 ==="

P1=$((BASE_PORT))
P2=$((BASE_PORT + 1))
P3=$((BASE_PORT + 2))

PEER_MAP="meta-1=http://127.0.0.1:${P1},meta-2=http://127.0.0.1:${P2},meta-3=http://127.0.0.1:${P3}"

# 停止可能已运行的单节点
systemctl stop rustio 2>/dev/null || true

for i in 1 2 3; do
  PORT=$((BASE_PORT + i - 1))
  DATA_DIR="${DATA_ROOT}/meta-${i}"
  mkdir -p "${DATA_DIR}"

  SERVICE_FILE="/etc/systemd/system/rustio-meta-${i}.service"
  ENV_FILE="/etc/rustio/env-meta-${i}"

  cat > "${ENV_FILE}" <<ENVEOF
RUSTIO_DATA_DIR=${DATA_DIR}
RUSTIO_ADDR=:${PORT}
RUSTIO_ROOT_USER=rustioadmin
RUSTIO_ROOT_PASSWORD=${ROOT_PASS}
RUSTIO_CONSOLE_USER=admin
RUSTIO_CONSOLE_PASSWORD=${ROOT_PASS}
RUSTIO_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || head -c 64 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 64)
RUSTIO_INTERNAL_TOKEN=${INTERNAL_TOKEN}
RUSTIO_METADATA_RAFT_NODE_ID=meta-${i}
RUSTIO_METADATA_RAFT_NETWORK_ENABLED=true
RUSTIO_METADATA_RAFT_NETWORK_STRICT=true
RUSTIO_METADATA_RAFT_PEERS=${PEER_MAP}
RUST_LOG=info
ENVEOF
  chmod 600 "${ENV_FILE}"

  cat > "${SERVICE_FILE}" <<SVCEOF
[Unit]
Description=RustIO cluster node meta-${i}
After=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${BINARY}
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable "rustio-meta-${i}"
  systemctl start "rustio-meta-${i}"
  echo "  ✅ meta-${i} 启动 (端口 ${PORT})"
done

# 等待集群选举
echo ""
echo "  等待集群选举..."
for _ in $(seq 1 30); do
  for p in ${P1} ${P2} ${P3}; do
    LID=$(curl -sf "http://127.0.0.1:${p}/health/ready" >/dev/null 2>&1 && \
      curl -s "http://127.0.0.1:${p}/api/v1/system/raft/status" \
        -H "Authorization: Basic $(printf 'admin:%s' "${ROOT_PASS}" | base64 | tr -d '\n')" 2>/dev/null \
        | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('leader_id',''))" 2>/dev/null) || true
    if [[ -n "${LID}" && "${LID}" != "None" && "${LID}" != "null" ]]; then
      echo "  ✅ Leader: ${LID}"
      break 2
    fi
  done
  sleep 2
done

echo ""
echo "╔══════════════════════════════════════╗"
echo "║     ✅ 3 节点集群部署完成             ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  节点:  meta-1(:${P1})  meta-2(:${P2})  meta-3(:${P3})"
echo "  用户:  rustioadmin"
echo "  密码:  ${ROOT_PASS}"
echo ""
echo "  服务管理:"
echo "    systemctl {start|stop|restart|status} rustio-meta-{1,2,3}"
echo ""
echo "  升级:"
echo "    bash scripts/rolling-upgrade/upgrade.sh --nodes <nodes.conf>"
