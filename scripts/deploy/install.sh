#!/usr/bin/env bash
# RustIO 一键部署:从 GitHub Releases 下载最新版本,安装为 systemd 服务并启动。
#
# 用法:
#   curl -sSL https://raw.githubusercontent.com/achunchunya/RustIO/main/scripts/deploy/install.sh | bash
#   或:
#   bash install.sh [--version v0.1.0] [--port 9000] [--data /opt/rustio/data]
#
# 可调环境变量:
#   RUSTIO_VERSION     指定版本(默认 latest)
#   RUSTIO_PORT        监听端口(默认 9000)
#   RUSTIO_DATA_DIR    数据目录(默认 /opt/rustio/data)
#   RUSTIO_USER        运行用户(默认 root)
#   RUSTIO_ROOT_USER   S3 root 用户名(默认 rustioadmin)
#   RUSTIO_ROOT_PASS   S3 root 密码(自动生成随机密码)
#   RUSTIO_JWT_SECRET  JWT 密钥(自动生成)
#   SKIP_SYSTEMD       1=跳过 systemd 注册(仅下载安装二进制)
set -euo pipefail

REPO="achunchunya/RustIO"
GITHUB_API="https://api.github.com/repos/${REPO}"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download"
# 国内可设镜像代理(如 https://ghproxy.com/ 或 https://gh-proxy.com/),前缀拼到完整 GitHub URL 前。
GH_MIRROR="${RUSTIO_GH_MIRROR:-}"
# curl 统一超时,避免连不上时无限挂起。
CURL_OPTS=(--connect-timeout 15 --retry 3 --retry-delay 2 --max-time 1800)
INSTALL_DIR="${RUSTIO_INSTALL_DIR:-/usr/local/bin}"
BINARY="${INSTALL_DIR}/rustio"
VERSION="${RUSTIO_VERSION:-}"
PORT="${RUSTIO_PORT:-9000}"
DATA_DIR="${RUSTIO_DATA_DIR:-/opt/rustio/data}"
RUN_USER="${RUSTIO_USER:-root}"
ROOT_USER="${RUSTIO_ROOT_USER:-rustioadmin}"
ROOT_PASS="${RUSTIO_ROOT_PASS:-}"
JWT_SECRET="${RUSTIO_JWT_SECRET:-}"
CONSOLE_PASS="${RUSTIO_CONSOLE_PASSWORD:-}"
CONSOLE_USER="${RUSTIO_CONSOLE_USER:-admin}"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"

# ── 参数解析 ──
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)  VERSION="$2"; shift 2 ;;
    --port)     PORT="$2"; shift 2 ;;
    --data)     DATA_DIR="$2"; shift 2 ;;
    --user)     RUN_USER="$2"; shift 2 ;;
    --help|-h)
      echo "用法: $0 [--version v0.1.0] [--port 9000] [--data /opt/rustio/data] [--user rustio]"
      exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

# ── 前置检查 ──
check_deps() {
  local missing=()
  for cmd in curl tar systemctl; do
    command -v "${cmd}" >/dev/null 2>&1 || missing+=("${cmd}")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "❌ 缺少依赖: ${missing[*]}"
    exit 1
  fi
}

# ── 平台检测 ──
detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "${os}" in
    linux)  os="linux" ;;
    *)      echo "❌ 仅支持 Linux 部署(当前: ${os})"; exit 1 ;;
  esac
  case "${arch}" in
    x86_64|amd64)  arch="amd64" ;;
    aarch64|arm64)  arch="arm64" ;;
    *)              echo "❌ 不支持的架构: ${arch}"; exit 1 ;;
  esac
  echo "rustio-${os}-${arch}"
}

# ── 生成随机密码 ──
gen_password() {
  python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)))" 2>/dev/null \
    || head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32
}

# ── 主流程 ──

echo "╔══════════════════════════════════════╗"
echo "║       RustIO 一键部署               ║"
echo "╚══════════════════════════════════════╝"
echo ""

check_deps

PLATFORM=$(detect_platform)
echo "  平台: ${PLATFORM}"

# 获取版本
if [[ -z "${VERSION}" ]]; then
  echo "  获取最新版本..."
  VERSION=$(curl -sSf "${CURL_OPTS[@]}" "${GH_MIRROR}${GITHUB_API}/releases/latest" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null)
  if [[ -z "${VERSION}" ]]; then
    echo "❌ 无法获取最新版本(可能是 api.github.com 不可达)。"
    echo "   请改用手动指定版本,例如:"
    echo "     ... | bash -s -- --version v1.0.0"
    echo "   国内网络可加镜像:"
    echo "     RUSTIO_GH_MIRROR=https://ghproxy.com/ ... | bash -s -- --version v1.0.0"
    exit 1
  fi
fi
echo "  版本: ${VERSION}"

# 下载
DOWNLOAD_URL="${GH_MIRROR}${DOWNLOAD_BASE}/${VERSION}/${PLATFORM}.tar.gz"
TMP_DIR=$(mktemp -d)
echo "  下载 ${DOWNLOAD_URL}..."
if ! curl -sSfL "${CURL_OPTS[@]}" "${DOWNLOAD_URL}" -o "${TMP_DIR}/rustio.tar.gz"; then
  echo "❌ 下载失败(GitHub 不可达或超时)。"
  echo "   国内网络可加镜像重试:"
  echo "     RUSTIO_GH_MIRROR=https://ghproxy.com/ ... | bash -s -- --version ${VERSION}"
  rm -rf "${TMP_DIR}"
  exit 1
fi
tar xzf "${TMP_DIR}/rustio.tar.gz" -C "${TMP_DIR}"

# 安装二进制
echo "  安装到 ${BINARY}..."
mkdir -p "${INSTALL_DIR}"
cp "${TMP_DIR}/rustio" "${BINARY}"
chmod +x "${BINARY}"
rm -rf "${TMP_DIR}"
echo "  ✅ 二进制安装完成"

# 生成凭据
[[ -z "${ROOT_PASS}" ]] && ROOT_PASS=$(gen_password)
[[ -z "${CONSOLE_PASS}" ]] && CONSOLE_PASS="${ROOT_PASS}"
[[ -z "${JWT_SECRET}" ]] && JWT_SECRET=$(gen_password)

# 创建数据目录
echo "  创建数据目录 ${DATA_DIR}..."
mkdir -p "${DATA_DIR}"
if [[ "${RUN_USER}" != "root" ]]; then
  chown -R "${RUN_USER}:${RUN_USER}" "${DATA_DIR}"
fi

# 写入环境配置
ENV_FILE="/etc/rustio/env"
echo "  写入配置 ${ENV_FILE}..."
mkdir -p /etc/rustio
cat > "${ENV_FILE}" <<ENVEOF
# RustIO 配置 — 自动生成于 $(date -u +%Y-%m-%dT%H:%M:%SZ)
RUSTIO_DATA_DIR=${DATA_DIR}
RUSTIO_ADDR=:${PORT}
RUSTIO_ROOT_USER=${ROOT_USER}
RUSTIO_ROOT_PASSWORD=${ROOT_PASS}
RUSTIO_CONSOLE_USER=${CONSOLE_USER}
RUSTIO_CONSOLE_PASSWORD=${CONSOLE_PASS}
RUSTIO_JWT_SECRET=${JWT_SECRET}
RUST_LOG=info
ENVEOF
chmod 600 "${ENV_FILE}"

# 注册 systemd 服务
if [[ "${SKIP_SYSTEMD}" != "1" ]]; then
  echo "  注册 systemd 服务..."
  SERVICE_FILE="/etc/systemd/system/rustio.service"
  cat > "${SERVICE_FILE}" <<SVCEOF
[Unit]
Description=RustIO S3-compatible storage server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
EnvironmentFile=/etc/rustio/env
ExecStart=${BINARY}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rustio

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable rustio
  systemctl start rustio

  # 等待启动
  echo "  等待服务启动..."
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:${PORT}/health/ready" >/dev/null 2>&1 && break
    sleep 1
  done

  if systemctl is-active rustio >/dev/null 2>&1; then
    echo "  ✅ RustIO 服务已启动"
  else
    echo "  ❌ 服务启动失败,查看日志: journalctl -u rustio -n 20"
    exit 1
  fi
fi

# ── 部署完成 ──
echo ""
echo "╔══════════════════════════════════════╗"
echo "║       ✅ 部署完成                    ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  S3 端点:     http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):${PORT}"
echo "  管理端:      http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):${PORT}"
echo "  S3 用户名:   ${ROOT_USER}"
echo "  S3 密码:     ${ROOT_PASS}"
echo "  控制台用户:  ${CONSOLE_USER}"
echo "  控制台密码:  ${CONSOLE_PASS}"
echo ""
echo "  配置文件:    /etc/rustio/env"
echo "  数据目录:    ${DATA_DIR}"
echo "  服务管理:    systemctl {start|stop|restart|status} rustio"
echo "  查看日志:    journalctl -u rustio -f"
echo ""
echo "  升级到新版本:"
echo "    curl -sSL https://raw.githubusercontent.com/${REPO}/main/scripts/rolling-upgrade/upgrade.sh | bash"
echo ""
echo "  ⚠️  请保存以上密码,此密码仅显示一次。"
