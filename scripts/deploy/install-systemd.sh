#!/usr/bin/env bash
# 把已在运行的 RustIO(手动 / nohup 启动)平滑接管为 systemd 服务。
#
# 与 install.sh 的区别:本脚本【不下载二进制、不生成新密码、不改数据目录】,
# 而是从当前运行进程的 /proc/<pid>/environ 与命令行【原样提取】数据目录与凭据,
# 写入 /etc/rustio/env,注册并启用 systemd,再停掉旧进程、由 systemd 接管启动。
#
# 用法(在服务器上以 root 运行):
#   curl -sSL https://raw.githubusercontent.com/achunchunya/RustIO/main/scripts/deploy/install-systemd.sh | bash
#   或: bash install-systemd.sh [--port 9000] [--data /opt/rustio/data] [--binary /usr/local/bin/rustio] [--user root]
#
# 若探测不到运行进程(已停止),可用 --data/--port 显式指定,并复用已有 /etc/rustio/env。
set -euo pipefail

INSTALL_DIR="${RUSTIO_INSTALL_DIR:-/usr/local/bin}"
BINARY="${RUSTIO_BINARY:-${INSTALL_DIR}/rustio}"
PORT="${RUSTIO_PORT:-9000}"
DATA_DIR="${RUSTIO_DATA_DIR:-}"
RUN_USER="${RUSTIO_USER:-root}"
ENV_FILE="/etc/rustio/env"
SERVICE_FILE="/etc/systemd/system/rustio.service"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)   PORT="$2"; shift 2 ;;
    --data)   DATA_DIR="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --user)   RUN_USER="$2"; shift 2 ;;
    --help|-h)
      echo "用法: $0 [--port 9000] [--data /opt/rustio/data] [--binary /usr/local/bin/rustio] [--user root]"
      exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

echo "=== RustIO systemd 接管 ==="

[[ "$(id -u)" == "0" ]] || { echo "❌ 请以 root 运行"; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "❌ 未找到 systemctl(非 systemd 系统)"; exit 1; }
[[ -x "${BINARY}" ]] || { echo "❌ 未找到 rustio 二进制: ${BINARY}"; exit 1; }

# ── 探测正在运行的 rustio 进程 ──
PID=""
if command -v lsof >/dev/null 2>&1; then
  PID=$(lsof -ti :"${PORT}" -sTCP:LISTEN 2>/dev/null | head -1 || true)
fi
if [[ -z "${PID}" ]]; then
  # 回退:按二进制路径匹配(排除本脚本自身)
  PID=$(pgrep -f "${BINARY}" 2>/dev/null | head -1 || true)
fi

# 收集环境变量:优先取运行进程 environ 里的 RUSTIO_*/MINIO_*/RUST_LOG,原样保留凭据。
declare -A ENVMAP
if [[ -n "${PID}" && -r "/proc/${PID}/environ" ]]; then
  echo "  探测到运行进程 PID=${PID},提取其配置..."
  while IFS= read -r -d '' kv; do
    case "${kv}" in
      RUSTIO_*=*|MINIO_*=*|RUST_LOG=*)
        ENVMAP["${kv%%=*}"]="${kv#*=}" ;;
    esac
  done < "/proc/${PID}/environ"

  # 数据目录:先看 environ,再从命令行参数解析(rustio server <DATA_DIR> --address ...)
  if [[ -z "${DATA_DIR}" ]]; then
    DATA_DIR="${ENVMAP[RUSTIO_DATA_DIR]:-}"
  fi
  if [[ -z "${DATA_DIR}" && -r "/proc/${PID}/cmdline" ]]; then
    mapfile -d '' -t CMD < "/proc/${PID}/cmdline"
    idx=1
    [[ "${CMD[1]:-}" == "server" ]] && idx=2
    j=${idx}
    while [[ ${j} -lt ${#CMD[@]} ]]; do
      a="${CMD[$j]}"
      case "${a}" in
        --address|-a) j=$((j+1)) ;;                 # 跳过其值
        --data-dir)   j=$((j+1)); DATA_DIR="${CMD[$j]:-}" ;;
        -*) ;;                                       # 其它选项忽略
        *) [[ -z "${DATA_DIR}" ]] && DATA_DIR="${a}" ;;
      esac
      j=$((j+1))
    done
  fi
else
  echo "  未探测到运行进程,将复用已有 ${ENV_FILE}(若存在)"
  if [[ -r "${ENV_FILE}" ]]; then
    while IFS= read -r line; do
      [[ "${line}" =~ ^[A-Z_]+=.*$ ]] || continue
      ENVMAP["${line%%=*}"]="${line#*=}"
      [[ "${line%%=*}" == "RUSTIO_DATA_DIR" && -z "${DATA_DIR}" ]] && DATA_DIR="${line#*=}"
    done < "${ENV_FILE}"
  fi
fi

if [[ -z "${DATA_DIR}" ]]; then
  echo "❌ 无法确定数据目录,请用 --data <目录> 显式指定"
  exit 1
fi

# 规范化 addr 与 data_dir 写回 map(供无参启动的 rustio 读取)
ENVMAP[RUSTIO_DATA_DIR]="${DATA_DIR}"
ENVMAP[RUSTIO_ADDR]="${ENVMAP[RUSTIO_ADDR]:-:${PORT}}"
ENVMAP[RUST_LOG]="${ENVMAP[RUST_LOG]:-info}"

echo "  数据目录: ${DATA_DIR}"
echo "  监听地址: ${ENVMAP[RUSTIO_ADDR]}"

# ── 写入 /etc/rustio/env(原样保留凭据,600 权限)──
mkdir -p /etc/rustio
{
  echo "# RustIO 配置 — 由 install-systemd.sh 接管生成于 $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for k in "${!ENVMAP[@]}"; do
    echo "${k}=${ENVMAP[$k]}"
  done
} > "${ENV_FILE}"
chmod 600 "${ENV_FILE}"
echo "  ✅ 已写入 ${ENV_FILE}"

# ── 注册 systemd 单元 ──
cat > "${SERVICE_FILE}" <<SVCEOF
[Unit]
Description=RustIO S3-compatible storage server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
EnvironmentFile=${ENV_FILE}
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
systemctl enable rustio >/dev/null 2>&1 || true

# ── 平滑切换:先停旧进程,再由 systemd 启动 ──
if [[ -n "${PID}" ]]; then
  echo "  停止旧进程 PID=${PID}..."
  kill "${PID}" 2>/dev/null || true
  for _ in $(seq 1 10); do kill -0 "${PID}" 2>/dev/null || break; sleep 1; done
  kill -9 "${PID}" 2>/dev/null || true
fi

echo "  启动 systemd 服务..."
systemctl restart rustio

echo "  等待健康检查..."
OK=0
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${PORT}/health/ready" >/dev/null 2>&1 && { OK=1; break; }
  sleep 1
done

if [[ "${OK}" == "1" ]] && systemctl is-active rustio >/dev/null 2>&1; then
  echo ""
  echo "=========================================="
  echo "  ✅ 已接管为 systemd 服务并启动"
  echo "=========================================="
  echo "  服务管理: systemctl {start|stop|restart|status} rustio"
  echo "  查看日志: journalctl -u rustio -f"
  echo "  配置文件: ${ENV_FILE}"
else
  echo "  ❌ 服务未就绪,查看日志: journalctl -u rustio -n 30"
  exit 1
fi
