#!/usr/bin/env bash
# RustIO 一键卸载:停止服务、删除 systemd 单元、二进制与配置。
#
# 用法:
#   curl -sSL https://raw.githubusercontent.com/achunchunya/RustIO/main/scripts/deploy/uninstall.sh | bash
#   # 连同数据一起删(不可恢复):
#   curl -sSL https://raw.githubusercontent.com/achunchunya/RustIO/main/scripts/deploy/uninstall.sh | bash -s -- --purge
#   # 或本地:
#   bash uninstall.sh [--purge] [--data /opt/rustio/data]
#
# 默认保留数据目录;加 --purge 才删数据。
set -uo pipefail

INSTALL_DIR="${RUSTIO_INSTALL_DIR:-/usr/local/bin}"
BINARY="${INSTALL_DIR}/rustio"
DATA_DIR="${RUSTIO_DATA_DIR:-/opt/rustio/data}"
PURGE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    --data)  DATA_DIR="$2"; shift 2 ;;
    --help|-h)
      echo "用法: $0 [--purge] [--data /opt/rustio/data]"
      echo "  --purge  连同数据目录一起删除(不可恢复)"
      echo "  --data   指定数据目录(默认 /opt/rustio/data)"
      exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

# root 检查
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "⚠ 需要 root 权限,请用 sudo 运行。"
  exit 1
fi

echo "╔══════════════════════════════════════╗"
echo "║       RustIO 卸载                    ║"
echo "╚══════════════════════════════════════╝"

# ── 停止并移除所有 rustio 相关 systemd 服务(单节点 + 集群 meta-N) ──
mapfile -t SERVICES < <(systemctl list-unit-files --type=service 2>/dev/null \
  | awk '/^rustio(-meta-[0-9]+)?\.service/ {print $1}')
# 兜底:直接扫单元目录
for f in /etc/systemd/system/rustio.service /etc/systemd/system/rustio-meta-*.service; do
  [[ -e "$f" ]] && SERVICES+=("$(basename "$f")")
done
# 去重
mapfile -t SERVICES < <(printf '%s\n' "${SERVICES[@]}" | sort -u)

if [[ ${#SERVICES[@]} -gt 0 ]]; then
  for svc in "${SERVICES[@]}"; do
    [[ -z "$svc" ]] && continue
    echo "  停止 ${svc}..."
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}"
    systemctl reset-failed "$svc" 2>/dev/null || true
  done
  systemctl daemon-reload
  echo "  ✅ systemd 服务已移除"
else
  echo "  未发现 rustio systemd 服务"
fi

# ── 兜底:杀掉残留进程 ──
if pgrep -x rustio >/dev/null 2>&1; then
  echo "  杀掉残留 rustio 进程..."
  pkill -x rustio 2>/dev/null || true
fi

# ── 删除二进制 ──
if [[ -f "$BINARY" ]]; then
  rm -f "$BINARY"
  echo "  ✅ 删除二进制 ${BINARY}"
fi

# ── 删除配置 ──
if [[ -d /etc/rustio ]]; then
  rm -rf /etc/rustio
  echo "  ✅ 删除配置 /etc/rustio"
fi

# ── 数据目录 ──
if [[ "$PURGE" == "1" ]]; then
  for d in "$DATA_DIR" /opt/rustio/cluster /opt/rustio; do
    if [[ -d "$d" ]]; then
      rm -rf "$d"
      echo "  ⚠️  已删除数据目录 ${d}"
    fi
  done
  rmdir /opt/rustio 2>/dev/null || true
else
  echo ""
  echo "  📦 数据目录已保留:${DATA_DIR}"
  echo "     如需彻底删除数据(不可恢复),重跑加 --purge:"
  echo "       ... uninstall.sh | bash -s -- --purge"
fi

echo ""
echo "╔══════════════════════════════════════╗"
echo "║       ✅ 卸载完成                    ║"
echo "╚══════════════════════════════════════╝"
