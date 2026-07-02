#!/usr/bin/env bash
# RustIO 部署管理脚本 —— 安装 / 升级 / 卸载 / systemd 接管 / 本地多节点集群 / 单机扩容为集群。
# 原来分散在多个文件里的逻辑(install.sh / install-systemd.sh / upgrade.sh /
# rolling-upgrade.sh / uninstall.sh)已合并到本文件,按子命令分发。
#
# 用法:
#   curl -sSL https://raw.githubusercontent.com/achunchunya/RustIO/main/scripts/install.sh | bash
#     — 无终端(管道)时直接安装,行为与以前的一键命令一致
#   bash <(curl -sSL https://raw.githubusercontent.com/achunchunya/RustIO/main/scripts/install.sh)
#     — 进程替换,保留终端,直接弹交互菜单
#   ./scripts/install.sh                — 本地直接跑,有终端则弹交互菜单
#   ./scripts/install.sh install [opts] — 显式安装
#   ./scripts/install.sh upgrade [opts] — 升级(单机或 --nodes 多节点滚动)
#   ./scripts/install.sh uninstall [opts]
#   ./scripts/install.sh systemd [opts] — 把已运行的手动/nohup 进程接管为 systemd
#   ./scripts/install.sh cluster [opts] — 本地多节点测试集群
#   ./scripts/install.sh expand [opts]  — 把已部署的单机实例扩容为集群
#   ./scripts/install.sh menu           — 强制进入交互菜单(管道模式下也可用,从 /dev/tty 读输入)
#
# 各子命令详细参数见: ./scripts/install.sh <子命令> --help
set -euo pipefail

REPO="achunchunya/RustIO"
GITHUB_API="https://api.github.com/repos/${REPO}"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download"
# 国内可设镜像代理(如 https://ghproxy.com/ 或 https://gh-proxy.com/),前缀拼到完整 GitHub URL 前。
GH_MIRROR="${RUSTIO_GH_MIRROR:-}"
CURL_OPTS=(--connect-timeout 15 --retry 3 --retry-delay 2 --max-time 1800)
INSTALL_DIR="${RUSTIO_INSTALL_DIR:-/usr/local/bin}"
BINARY="${INSTALL_DIR}/rustio"
ENV_FILE="/etc/rustio/env"
SERVICE_FILE="/etc/systemd/system/rustio.service"

# ── 公共函数 ──

log()  { echo "[RustIO] $*"; }
fail() { echo "[RustIO] ❌ $*" >&2; exit 1; }

# 从 /dev/tty 读交互输入(在 curl | bash 管道模式下 stdin 被脚本源码占用,必须走 /dev/tty)。
# prompt <变量名> <提示文字> [默认值]
prompt() {
  local __var="$1" __msg="$2" __default="${3:-}"
  local __ans=""
  if [[ -r /dev/tty ]]; then
    read -r -p "${__msg}" __ans < /dev/tty || true
  else
    read -r -p "${__msg}" __ans || true
  fi
  printf -v "${__var}" '%s' "${__ans:-${__default}}"
}

detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "${os}" in
    linux)  os="linux" ;;
    darwin) os="darwin" ;;
    *)      fail "不支持的操作系统: ${os}" ;;
  esac
  case "${arch}" in
    x86_64|amd64)  arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)             fail "不支持的架构: ${arch}" ;;
  esac
  echo "rustio-${os}-${arch}"
}

gen_password() {
  python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)))" 2>/dev/null \
    || head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32
}

get_latest_version() {
  curl -sSf "${CURL_OPTS[@]}" "${GH_MIRROR}${GITHUB_API}/releases/latest" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null
}

get_current_version() {
  local binary_path="$1"
  if [[ -x "${binary_path}" ]]; then
    "${binary_path}" --version 2>/dev/null | head -1 || echo "unknown"
  else
    echo "未安装"
  fi
}

# 下载并解压到临时目录,成功时把二进制路径打印到 stdout(供 $(...) 捕获),
# 进度/错误信息一律走 stderr,避免污染返回值。
download_binary() {
  local version="$1" asset="$2"
  local url="${GH_MIRROR}${DOWNLOAD_BASE}/${version}/${asset}.tar.gz"
  local tmp_dir
  tmp_dir=$(mktemp -d)
  echo "  下载 ${url}..." >&2
  if ! curl -sSfL "${CURL_OPTS[@]}" "${url}" -o "${tmp_dir}/${asset}.tar.gz"; then
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

# 同目录临时文件 + rename 原子替换,规避覆盖运行中二进制时的 "Text file busy"(ETXTBSY):
# rename 不触碰运行中的旧 inode,进程照常运行,新名字指向新 inode,随后重启即加载新二进制。
install_binary_atomic() {
  local src="$1" dest="$2"
  local tmp_dest="${dest}.new.$$"
  cp "${src}" "${tmp_dest}"
  chmod +x "${tmp_dest}"
  mv -f "${tmp_dest}" "${dest}"
}

wait_healthy() {
  local host="$1" port="$2" timeout="${3:-30}"
  local _
  for _ in $(seq 1 "${timeout}"); do
    curl -sf "http://${host}:${port}/health/ready" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

is_local_host() {
  [[ "$1" == "127.0.0.1" || "$1" == "localhost" || "$1" == "0.0.0.0" ]]
}

write_systemd_unit() {
  local service_file="$1" run_user="$2" env_file="$3" binary="$4" description="${5:-RustIO S3-compatible storage server}"
  cat > "${service_file}" <<SVCEOF
[Unit]
Description=${description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${run_user}
EnvironmentFile=${env_file}
ExecStart=${binary}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rustio

[Install]
WantedBy=multi-user.target
SVCEOF
}

# 查询节点当前 raft leader_id;查不到返回非零。
get_raft_leader() {
  local host="$1" port="$2" user="${3:-admin}" pass="${4:-rustio-admin}"
  local tk
  tk=$(curl -s -X POST "http://${host}:${port}/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('access_token',''))" 2>/dev/null || true)
  [[ -z "${tk}" ]] && return 1
  local lid
  lid=$(curl -s "http://${host}:${port}/api/v1/system/raft/status" \
    -H "Authorization: Bearer ${tk}" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('leader_id',''))" 2>/dev/null || true)
  if [[ -n "${lid}" && "${lid}" != "None" && "${lid}" != "null" ]]; then
    echo "${lid}"
    return 0
  fi
  return 1
}

# ── install ──

cmd_install() {
  local version="${RUSTIO_VERSION:-}"
  local port="${RUSTIO_PORT:-9000}"
  local data_dir="${RUSTIO_DATA_DIR:-/opt/rustio/data}"
  local run_user="${RUSTIO_USER:-root}"
  local root_user="${RUSTIO_ROOT_USER:-rustioadmin}"
  local root_pass="${RUSTIO_ROOT_PASS:-}"
  local jwt_secret="${RUSTIO_JWT_SECRET:-}"
  local console_pass="${RUSTIO_CONSOLE_PASSWORD:-}"
  local console_user="${RUSTIO_CONSOLE_USER:-admin}"
  local skip_systemd="${SKIP_SYSTEMD:-0}"
  # 集群加入参数(可选;由 expand 子命令给出的加入命令自动传入)
  local cluster_node_id="${RUSTIO_CLUSTER_NODE_ID:-}"
  local cluster_seeds="${RUSTIO_CLUSTER_SEEDS:-}"
  local cluster_zone="${RUSTIO_CLUSTER_NODE_ZONE:-default}"
  local cluster_token="${RUSTIO_INTERNAL_TOKEN:-}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) version="$2"; shift 2 ;;
      --port)    port="$2"; shift 2 ;;
      --data)    data_dir="$2"; shift 2 ;;
      --user)    run_user="$2"; shift 2 ;;
      --help|-h)
        echo "用法: $0 install [--version v1.2.3] [--port 9000] [--data /opt/rustio/data] [--user rustio]"
        echo "可调环境变量: RUSTIO_VERSION RUSTIO_PORT RUSTIO_DATA_DIR RUSTIO_USER"
        echo "              RUSTIO_ROOT_USER RUSTIO_ROOT_PASS RUSTIO_JWT_SECRET"
        echo "              RUSTIO_CONSOLE_USER RUSTIO_CONSOLE_PASSWORD SKIP_SYSTEMD"
        echo "              RUSTIO_CLUSTER_NODE_ID RUSTIO_CLUSTER_SEEDS RUSTIO_INTERNAL_TOKEN(加入已有集群时使用)"
        return 0 ;;
      *) fail "未知参数: $1(install)" ;;
    esac
  done

  echo "╔══════════════════════════════════════╗"
  echo "║       RustIO 一键部署               ║"
  echo "╚══════════════════════════════════════╝"
  echo ""

  command -v curl >/dev/null 2>&1 || fail "缺少依赖: curl"
  command -v tar  >/dev/null 2>&1 || fail "缺少依赖: tar"
  command -v systemctl >/dev/null 2>&1 || fail "缺少依赖: systemctl(仅支持 systemd 系统;本地测试集群请用 cluster 子命令)"

  local platform
  platform=$(detect_platform)
  echo "  平台: ${platform}"

  if [[ -z "${version}" ]]; then
    echo "  获取最新版本..."
    version=$(get_latest_version)
    if [[ -z "${version}" ]]; then
      fail "无法获取最新版本(可能是 api.github.com 不可达)。请用 --version 手动指定,国内网络可设 RUSTIO_GH_MIRROR。"
    fi
  fi
  echo "  版本: ${version}"

  local new_bin
  new_bin=$(download_binary "${version}" "${platform}") || exit 1
  echo "  ✅ 下载完成: ${new_bin}"

  echo "  安装到 ${BINARY}..."
  mkdir -p "${INSTALL_DIR}"
  cp "${new_bin}" "${BINARY}"
  chmod +x "${BINARY}"
  rm -rf "$(dirname "${new_bin}")"
  echo "  ✅ 二进制安装完成"

  [[ -z "${root_pass}" ]] && root_pass=$(gen_password)
  [[ -z "${console_pass}" ]] && console_pass="${root_pass}"
  [[ -z "${jwt_secret}" ]] && jwt_secret=$(gen_password)

  echo "  创建数据目录 ${data_dir}..."
  mkdir -p "${data_dir}"
  if [[ "${run_user}" != "root" ]]; then
    chown -R "${run_user}:${run_user}" "${data_dir}"
  fi

  echo "  写入配置 ${ENV_FILE}..."
  mkdir -p /etc/rustio
  cat > "${ENV_FILE}" <<ENVEOF
# RustIO 配置 — 自动生成于 $(date -u +%Y-%m-%dT%H:%M:%SZ)
RUSTIO_DATA_DIR=${data_dir}
RUSTIO_ADDR=:${port}
RUSTIO_ROOT_USER=${root_user}
RUSTIO_ROOT_PASSWORD=${root_pass}
RUSTIO_CONSOLE_USER=${console_user}
RUSTIO_CONSOLE_PASSWORD=${console_pass}
RUSTIO_JWT_SECRET=${jwt_secret}
RUST_LOG=info
ENVEOF

  # 若带了集群加入参数,追加集群配置(用于 expand 子命令生成的"新机器加入"一键命令)。
  if [[ -n "${cluster_node_id}" ]]; then
    local self_ip
    self_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [[ -z "${self_ip}" ]] && self_ip="127.0.0.1"
    [[ -z "${cluster_token}" ]] && cluster_token=$(gen_password)
    cat >> "${ENV_FILE}" <<ENVEOF2
RUSTIO_CLUSTER_NODE_ID=${cluster_node_id}
RUSTIO_CLUSTER_NODE_NAME=meta-${cluster_node_id}
RUSTIO_CLUSTER_NODE_ADDR=http://${self_ip}:${port}
RUSTIO_CLUSTER_NODE_ZONE=${cluster_zone}
RUSTIO_CLUSTER_SEEDS=${cluster_seeds}
RUSTIO_INTERNAL_TOKEN=${cluster_token}
RUSTIO_METADATA_RAFT_NETWORK_ENABLED=true
RUSTIO_METADATA_RAFT_NODE_ID=meta-${cluster_node_id}
RUSTIO_METADATA_RAFT_PEERS=${cluster_seeds}
ENVEOF2
    echo "  ✅ 已写入集群加入配置(node_id=${cluster_node_id})"
  fi
  chmod 600 "${ENV_FILE}"

  if [[ "${skip_systemd}" != "1" ]]; then
    echo "  注册 systemd 服务..."
    write_systemd_unit "${SERVICE_FILE}" "${run_user}" "${ENV_FILE}" "${BINARY}"
    systemctl daemon-reload
    systemctl enable rustio
    systemctl start rustio

    echo "  等待服务启动..."
    if wait_healthy "127.0.0.1" "${port}" 30; then
      echo "  ✅ RustIO 服务已启动"
    else
      fail "服务启动失败,查看日志: journalctl -u rustio -n 20"
    fi
  fi

  echo ""
  echo "╔══════════════════════════════════════╗"
  echo "║       ✅ 部署完成                    ║"
  echo "╚══════════════════════════════════════╝"
  echo ""
  local display_ip
  display_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  [[ -z "${display_ip}" ]] && display_ip="localhost"
  echo "  S3 端点:     http://${display_ip}:${port}"
  echo "  管理端:      http://${display_ip}:${port}"
  echo "  S3 用户名:   ${root_user}"
  echo "  S3 密码:     ${root_pass}"
  echo "  控制台用户:  ${console_user}"
  echo "  控制台密码:  ${console_pass}"
  echo ""
  echo "  配置文件:    ${ENV_FILE}"
  echo "  数据目录:    ${data_dir}"
  echo "  服务管理:    systemctl {start|stop|restart|status} rustio"
  echo "  查看日志:    journalctl -u rustio -f"
  echo ""

  # 把部署脚本存到服务器上,以后直接 run rustio-deploy upgrade 等。
  local deploy_bin="${INSTALL_DIR}/rustio-deploy"
  cp "${BASH_SOURCE[0]}" "${deploy_bin}" 2>/dev/null || true
  chmod +x "${deploy_bin}" 2>/dev/null || true
  echo "  部署工具已留存: ${deploy_bin}"
  echo "    ${deploy_bin} upgrade    # 升级"
  echo "    ${deploy_bin} menu       # 交互菜单"
  echo ""
  echo "  ⚠️  请保存以上密码,此密码仅显示一次。"
}

# ── uninstall ──

cmd_uninstall() {
  local data_dir="${RUSTIO_DATA_DIR:-/opt/rustio/data}"
  local purge=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge) purge=1; shift ;;
      --data)  data_dir="$2"; shift 2 ;;
      --help|-h)
        echo "用法: $0 uninstall [--purge] [--data /opt/rustio/data]"
        echo "  --purge  连同数据目录一起删除(不可恢复)"
        echo "  --data   指定数据目录(默认 /opt/rustio/data)"
        return 0 ;;
      *) fail "未知参数: $1(uninstall)" ;;
    esac
  done

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    fail "需要 root 权限,请用 sudo 运行。"
  fi

  echo "╔══════════════════════════════════════╗"
  echo "║       RustIO 卸载                    ║"
  echo "╚══════════════════════════════════════╝"

  # 停止并移除所有 rustio 相关 systemd 服务(单节点 + 集群 meta-N)
  local -a services=()
  mapfile -t services < <(systemctl list-unit-files --type=service 2>/dev/null \
    | awk '/^rustio(-meta-[0-9]+)?\.service/ {print $1}')
  local f
  for f in /etc/systemd/system/rustio.service /etc/systemd/system/rustio-meta-*.service; do
    [[ -e "$f" ]] && services+=("$(basename "$f")")
  done
  mapfile -t services < <(printf '%s\n' "${services[@]+"${services[@]}"}" | sort -u)

  if [[ ${#services[@]} -gt 0 ]]; then
    local svc
    for svc in "${services[@]+"${services[@]}"}"; do
      [[ -z "$svc" ]] && continue
      echo "  停止 ${svc}..."
      # systemctl stop 超时/卡住时用 kill -9 兜底,不会永远 hang。
      timeout 30 systemctl stop "$svc" 2>/dev/null || {
        echo "  ⚠️  正常停止超时,强制杀掉..."
        systemctl kill -s KILL "$svc" 2>/dev/null || true
      }
      systemctl disable "$svc" 2>/dev/null || true
      rm -f "/etc/systemd/system/${svc}"
      systemctl reset-failed "$svc" 2>/dev/null || true
    done
    systemctl daemon-reload
    echo "  ✅ systemd 服务已移除"
  else
    echo "  未发现 rustio systemd 服务"
  fi

  if pgrep -x rustio >/dev/null 2>&1; then
    echo "  杀掉残留 rustio 进程..."
    pkill -x rustio 2>/dev/null || true
  fi

  if [[ -f "${BINARY}" ]]; then
    rm -f "${BINARY}"
    echo "  ✅ 删除二进制 ${BINARY}"
  fi

  if [[ -d /etc/rustio ]]; then
    rm -rf /etc/rustio
    echo "  ✅ 删除配置 /etc/rustio"
  fi

  if [[ "${purge}" == "1" ]]; then
    local d
    for d in "${data_dir}" /opt/rustio/cluster /opt/rustio "${HOME}/.rustio"; do
      if [[ -d "$d" ]]; then
        rm -rf "$d"
        echo "  ⚠️  已删除数据目录 ${d}"
      fi
    done
    rmdir /opt/rustio 2>/dev/null || true
  else
    echo ""
    echo "  📦 数据目录已保留:${data_dir}"
    echo "     如需彻底删除数据(不可恢复),重跑加 --purge:"
    echo "       ... install.sh uninstall --purge"
  fi

  echo ""
  echo "╔══════════════════════════════════════╗"
  echo "║       ✅ 卸载完成                    ║"
  echo "╚══════════════════════════════════════╝"
}

# ── systemd(把已运行的手动/nohup 进程接管为 systemd) ──

cmd_systemd() {
  local port="${RUSTIO_PORT:-9000}"
  local data_dir="${RUSTIO_DATA_DIR:-}"
  local run_user="${RUSTIO_USER:-root}"
  local binary="${RUSTIO_BINARY:-${BINARY}}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port)   port="$2"; shift 2 ;;
      --data)   data_dir="$2"; shift 2 ;;
      --binary) binary="$2"; shift 2 ;;
      --user)   run_user="$2"; shift 2 ;;
      --help|-h)
        echo "用法: $0 systemd [--port 9000] [--data /opt/rustio/data] [--binary /usr/local/bin/rustio] [--user root]"
        echo "把已在运行的 RustIO(手动/nohup 启动)平滑接管为 systemd 服务:"
        echo "从运行进程的 /proc/<pid>/environ 与命令行原样提取数据目录与凭据,不生成新密码。"
        return 0 ;;
      *) fail "未知参数: $1(systemd)" ;;
    esac
  done

  echo "=== RustIO systemd 接管 ==="

  [[ "$(id -u)" == "0" ]] || fail "请以 root 运行"
  command -v systemctl >/dev/null 2>&1 || fail "未找到 systemctl(非 systemd 系统)"
  [[ -x "${binary}" ]] || fail "未找到 rustio 二进制: ${binary}"

  local pid=""
  if command -v lsof >/dev/null 2>&1; then
    pid=$(lsof -ti :"${port}" -sTCP:LISTEN 2>/dev/null | head -1 || true)
  fi
  if [[ -z "${pid}" ]]; then
    pid=$(pgrep -f "${binary}" 2>/dev/null | head -1 || true)
  fi

  local -A envmap=()
  if [[ -n "${pid}" && -r "/proc/${pid}/environ" ]]; then
    echo "  探测到运行进程 PID=${pid},提取其配置..."
    local kv
    while IFS= read -r -d '' kv; do
      case "${kv}" in
        RUSTIO_*=*|MINIO_*=*|RUST_LOG=*)
          envmap["${kv%%=*}"]="${kv#*=}" ;;
      esac
    done < "/proc/${pid}/environ"

    if [[ -z "${data_dir}" ]]; then
      data_dir="${envmap[RUSTIO_DATA_DIR]:-}"
    fi
    if [[ -z "${data_dir}" && -r "/proc/${pid}/cmdline" ]]; then
      local -a cmd=()
      mapfile -d '' -t cmd < "/proc/${pid}/cmdline"
      local idx=1
      [[ "${cmd[1]:-}" == "server" ]] && idx=2
      local j=${idx}
      while [[ ${j} -lt ${#cmd[@]} ]]; do
        local a="${cmd[$j]}"
        case "${a}" in
          --address|-a) j=$((j+1)) ;;
          --data-dir)   j=$((j+1)); data_dir="${cmd[$j]:-}" ;;
          -*) ;;
          *) [[ -z "${data_dir}" ]] && data_dir="${a}" ;;
        esac
        j=$((j+1))
      done
    fi
  else
    echo "  未探测到运行进程,将复用已有 ${ENV_FILE}(若存在)"
    if [[ -r "${ENV_FILE}" ]]; then
      local line
      while IFS= read -r line; do
        [[ "${line}" =~ ^[A-Z_]+=.*$ ]] || continue
        envmap["${line%%=*}"]="${line#*=}"
        [[ "${line%%=*}" == "RUSTIO_DATA_DIR" && -z "${data_dir}" ]] && data_dir="${line#*=}"
      done < "${ENV_FILE}"
    fi
  fi

  [[ -z "${data_dir}" ]] && fail "无法确定数据目录,请用 --data <目录> 显式指定"

  envmap[RUSTIO_DATA_DIR]="${data_dir}"
  envmap[RUSTIO_ADDR]="${envmap[RUSTIO_ADDR]:-:${port}}"
  envmap[RUST_LOG]="${envmap[RUST_LOG]:-info}"

  echo "  数据目录: ${data_dir}"
  echo "  监听地址: ${envmap[RUSTIO_ADDR]}"

  mkdir -p /etc/rustio
  {
    echo "# RustIO 配置 — 由 install.sh systemd 接管生成于 $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local k
    for k in "${!envmap[@]}"; do
      echo "${k}=${envmap[$k]}"
    done
  } > "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
  echo "  ✅ 已写入 ${ENV_FILE}"

  write_systemd_unit "${SERVICE_FILE}" "${run_user}" "${ENV_FILE}" "${binary}"
  systemctl daemon-reload
  systemctl enable rustio >/dev/null 2>&1 || true

  if [[ -n "${pid}" ]]; then
    echo "  停止旧进程 PID=${pid}..."
    kill "${pid}" 2>/dev/null || true
    local _
    for _ in $(seq 1 10); do kill -0 "${pid}" 2>/dev/null || break; sleep 1; done
    kill -9 "${pid}" 2>/dev/null || true
  fi

  echo "  启动 systemd 服务..."
  systemctl restart rustio

  echo "  等待健康检查..."
  if wait_healthy "127.0.0.1" "${port}" 30; then
    echo ""
    echo "=========================================="
    echo "  ✅ 已接管为 systemd 服务并启动"
    echo "=========================================="
    echo "  服务管理: systemctl {start|stop|restart|status} rustio"
    echo "  查看日志: journalctl -u rustio -f"
    echo "  配置文件: ${ENV_FILE}"
  else
    fail "服务未就绪,查看日志: journalctl -u rustio -n 30"
  fi
}

# ── upgrade(单机原子替换 + 重启;--nodes 走多节点滚动升级) ──

cmd_upgrade() {
  local target_version=""
  local node_config=""
  local binary_path="${RUSTIO_BINARY:-${BINARY}}"
  local timeout="${UPGRADE_TIMEOUT:-120}"
  local settle="${UPGRADE_SETTLE:-10}"
  local dry_run="${UPGRADE_DRY_RUN:-0}"
  local ssh_user="${SSH_USER:-root}"
  local ssh_key="${SSH_KEY:-}"
  local ssh_opts="${SSH_OPTS:-}"
  # 探测 raft leader 用的管理账号;集群若非默认凭据(如 cluster 子命令随机生成的密码),
  # 用 --api-user/--api-password 指定,否则回退默认 admin/rustio-admin。
  local api_user="${RUSTIO_UPGRADE_API_USER:-admin}"
  local api_password="${RUSTIO_UPGRADE_API_PASSWORD:-rustio-admin}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)      target_version="$2"; shift 2 ;;
      --nodes)        node_config="$2"; shift 2 ;;
      --binary)       binary_path="$2"; shift 2 ;;
      --dry-run)      dry_run=1; shift ;;
      --api-user)     api_user="$2"; shift 2 ;;
      --api-password) api_password="$2"; shift 2 ;;
      --help|-h)
        echo "用法: $0 upgrade [--version v1.2.3] [--binary /path/to/rustio]"
        echo "      $0 upgrade --nodes <nodes.conf> [--dry-run] [--api-user admin --api-password xxx]"
        echo ""
        echo "节点配置文件格式(每行,空行/# 跳过): node_id ssh_host api_port data_dir [binary_path]"
        echo "  meta-1  10.0.1.1  9000  /opt/rustio/data/meta-1  /usr/local/bin/rustio"
        echo "  host 为 127.0.0.1/localhost 时按本机节点处理(kill+原子替换),否则走 SSH+SCP。"
        echo ""
        echo "环境变量: RUSTIO_BINARY UPGRADE_TIMEOUT(默认120) UPGRADE_SETTLE(默认10)"
        echo "          SSH_USER(默认root) SSH_KEY SSH_OPTS"
        return 0 ;;
      *) fail "未知参数: $1(upgrade)" ;;
    esac
  done

  local ssh_cmd="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
  [[ -n "${ssh_key}" ]] && ssh_cmd="${ssh_cmd} -i ${ssh_key}"
  [[ -n "${ssh_opts}" ]] && ssh_cmd="${ssh_cmd} ${ssh_opts}"

  echo "=== RustIO 升级 ==="

  local platform
  platform=$(detect_platform)

  if [[ -z "${target_version}" ]]; then
    target_version=$(get_latest_version)
    [[ -z "${target_version}" ]] && fail "无法获取最新版本(检查网络或 GitHub API 限制),可用 --version 手动指定"
  fi
  echo "  目标版本: ${target_version}"

  if [[ -z "${node_config}" ]]; then
    # ── 单机模式 ──
    local current
    current=$(get_current_version "${binary_path}")
    echo "  当前版本: ${current}"
    if [[ "${current}" == *"${target_version#v}"* ]]; then
      echo "  已是最新版本,无需升级"
      return 0
    fi
    echo "  平台: ${platform}"
    local new_bin
    new_bin=$(download_binary "${target_version}" "${platform}") || exit 1
    echo "  ✅ 下载完成: ${new_bin}"

    install_binary_atomic "${new_bin}" "${binary_path}"
    rm -rf "$(dirname "${new_bin}")"

    if systemctl is-active rustio >/dev/null 2>&1; then
      echo "  重启 rustio 服务..."
      systemctl restart rustio
    else
      echo "  ⚠️  rustio 未作为 systemd 服务运行,请手动重启:"
      echo "     ${binary_path} server <data_dir> --address :9000"
    fi

    echo ""
    echo "=========================================="
    echo "  ✅ 升级完成 → ${target_version}"
    echo "=========================================="
    return 0
  fi

  # ── 多节点滚动升级 ──
  [[ -f "${node_config}" ]] || fail "节点配置文件不存在: ${node_config}"

  local -a node_ids=() node_hosts=() node_ports=() node_datadirs=() node_bins=()
  local line nid host port dir bin_extra
  while IFS= read -r line; do
    line=$(echo "${line}" | sed 's/#.*//' | xargs)
    [[ -z "${line}" ]] && continue
    read -r nid host port dir bin_extra <<< "${line}"
    node_ids+=("${nid}")
    node_hosts+=("${host}")
    node_ports+=("${port}")
    node_datadirs+=("${dir}")
    node_bins+=("${bin_extra:-${binary_path}}")
  done < "${node_config}"

  [[ ${#node_ids[@]} -eq 0 ]] && fail "节点配置文件为空或格式不对: ${node_config}"

  echo "  平台: ${platform}"
  local new_bin
  new_bin=$(download_binary "${target_version}" "${platform}") || exit 1
  echo "  ✅ 下载完成: ${new_bin}"

  echo "  节点数: ${#node_ids[@]}"
  local i
  for i in "${!node_ids[@]}"; do
    echo "    ${node_ids[$i]} → ${node_hosts[$i]}:${node_ports[$i]}"
  done

  echo ""
  echo "=== 预检:集群当前状态 ==="
  local all_reachable=true
  for i in "${!node_hosts[@]}"; do
    if wait_healthy "${node_hosts[$i]}" "${node_ports[$i]}" 5; then
      echo "  ✅ ${node_ids[$i]} 可达"
    else
      echo "  ❌ ${node_ids[$i]} 不可达"
      all_reachable=false
    fi
  done
  if [[ "${all_reachable}" == "false" ]]; then
    rm -rf "$(dirname "${new_bin}")"
    fail "部分节点不可达,中止升级"
  fi

  local leader=""
  for i in "${!node_hosts[@]}"; do
    leader=$(get_raft_leader "${node_hosts[$i]}" "${node_ports[$i]}" "${api_user}" "${api_password}" || true)
    [[ -n "${leader}" ]] && break
  done
  echo "  当前 leader: ${leader:-未知}"

  # follower 先,leader 最后
  local -a order=()
  local leader_idx=-1
  for i in "${!node_ids[@]}"; do
    if [[ "${node_ids[$i]}" == "${leader}" ]]; then
      leader_idx=$i
    else
      order+=("$i")
    fi
  done
  [[ ${leader_idx} -ge 0 ]] && order+=("${leader_idx}")

  echo ""
  echo "=== 开始滚动升级 ==="
  [[ "${dry_run}" == "1" ]] && echo "  ⚠️  DRY-RUN 模式,仅打印计划"
  local total=${#order[@]} current_n=0 pass_n=0 fail_n=0 aborted=0
  for i in "${order[@]}"; do
    current_n=$((current_n + 1))
    nid="${node_ids[$i]}"; host="${node_hosts[$i]}"; port="${node_ports[$i]}"
    dir="${node_datadirs[$i]}"; local bin="${node_bins[$i]}"
    echo ""
    echo "=== [${current_n}/${total}] 升级 ${nid} (${host}:${port}) ==="

    if [[ "${dry_run}" == "1" ]]; then
      echo "  [DRY-RUN] 跳过实际执行"
      continue
    fi

    echo "  停止 ${nid}..."
    if is_local_host "${host}"; then
      local pid
      pid=$(lsof -ti :"${port}" 2>/dev/null || true)
      [[ -n "${pid}" ]] && { kill "${pid}" 2>/dev/null || true; sleep 1; kill -9 "${pid}" 2>/dev/null || true; }
    else
      ${ssh_cmd} "${ssh_user}@${host}" "pkill -f '${bin}.*server.*${dir}' 2>/dev/null; sleep 1; pkill -9 -f '${bin}.*server.*${dir}' 2>/dev/null" || true
    fi
    sleep 1

    echo "  部署新二进制..."
    if is_local_host "${host}"; then
      install_binary_atomic "${new_bin}" "${bin}"
    else
      scp -o StrictHostKeyChecking=no ${ssh_key:+-i ${ssh_key}} "${new_bin}" "${ssh_user}@${host}:${bin}.new"
      ${ssh_cmd} "${ssh_user}@${host}" "mv '${bin}.new' '${bin}' && chmod +x '${bin}'"
    fi

    echo "  启动 ${nid}..."
    if is_local_host "${host}"; then
      if systemctl is-active "rustio-${nid}" >/dev/null 2>&1; then
        systemctl restart "rustio-${nid}"
      elif systemctl is-active rustio >/dev/null 2>&1; then
        systemctl restart rustio
      else
        nohup "${bin}" server "${dir}" --address ":${port}" >/dev/null 2>&1 &
      fi
    else
      ${ssh_cmd} "${ssh_user}@${host}" "
        if systemctl is-active rustio-${nid} >/dev/null 2>&1; then
          systemctl restart rustio-${nid}
        elif systemctl is-active rustio >/dev/null 2>&1; then
          systemctl restart rustio
        else
          pkill -f '${bin}.*server' 2>/dev/null || true
          sleep 1
          nohup ${bin} server ${dir} --address :${port} >/dev/null 2>&1 &
        fi
      "
    fi

    echo "  等待健康检查..."
    if ! wait_healthy "${host}" "${port}" "${timeout}"; then
      echo "  ❌ ${nid} 健康检查超时(${timeout}s)"
      fail_n=$((fail_n+1)); aborted=1
      break
    fi
    echo "  ✅ ${nid} 健康检查通过"
    pass_n=$((pass_n+1))

    echo "  等待 Raft 追平(${settle}s)..."
    sleep "${settle}"

    local lid="" j
    for j in "${!node_hosts[@]}"; do
      lid=$(get_raft_leader "${node_hosts[$j]}" "${node_ports[$j]}" "${api_user}" "${api_password}" || true)
      [[ -n "${lid}" ]] && break
    done
    if [[ -z "${lid}" ]]; then
      echo "  ❌ 升级 ${nid} 后集群无 leader"
      fail_n=$((fail_n+1)); aborted=1
      break
    fi
    echo "  ✅ 集群 leader: ${lid}"
  done

  rm -rf "$(dirname "${new_bin}")"

  echo ""
  echo "=== 最终验证 ==="
  if [[ "${dry_run}" != "1" && "${aborted}" == "0" ]]; then
    sleep 3
    local final_leader="" k
    for k in "${!node_hosts[@]}"; do
      final_leader=$(get_raft_leader "${node_hosts[$k]}" "${node_ports[$k]}" "${api_user}" "${api_password}" || true)
      [[ -n "${final_leader}" ]] && break
    done
    if [[ -n "${final_leader}" ]]; then
      echo "  ✅ 集群 leader: ${final_leader}"
    else
      echo "  ❌ 集群无 leader"
    fi
    for k in "${!node_hosts[@]}"; do
      if wait_healthy "${node_hosts[$k]}" "${node_ports[$k]}" 5; then
        echo "  ✅ ${node_ids[$k]} 升级后可达"
      else
        echo "  ❌ ${node_ids[$k]} 升级后不可达"
      fi
    done
  fi

  echo ""
  echo "=========================================="
  echo "  滚动升级完成: 通过 ${pass_n} / 失败 ${fail_n}"
  [[ "${aborted}" == "1" ]] && echo "  ⚠️  升级中止,部分节点可能仍在运行旧版本"
  echo "=========================================="
  return "${fail_n}"
}

# ── cluster(本地多节点测试集群) ──

cluster_up() {
  local num_nodes="$1" base_port="$2" data_root="$3" version="$4"
  local join_seed="${5:-}"   # 格式: node_id=http://host:port,加入已有集群做种子
  local join_token="${6:-}"  # 加入时用的内部通信令牌

  echo "=== RustIO 本地多节点集群 ==="
  echo "  节点数: ${num_nodes}"
  echo "  起始端口: ${base_port}"
  echo "  数据目录: ${data_root}"
  if [[ -n "${join_seed}" ]]; then
    echo "  加入已有集群: ${join_seed}"
  fi

  local use_systemd=0
  if command -v systemctl >/dev/null 2>&1; then
    if [[ "$(id -u)" == "0" ]]; then
      use_systemd=1
    else
      echo ""
      echo "  检测到 systemd,但当前非 root。注册为持久化 systemd 服务(开机自启)需要 root 权限。"
      local ans
      prompt ans "  用 sudo 重新执行以获得持久化? [Y/n] " "Y"
      if [[ ! "${ans}" =~ ^[Nn]$ ]]; then
        exec sudo -E "$0" cluster --nodes "${num_nodes}" --base-port "${base_port}" --data "${data_root}" \
          ${version:+--version "${version}"} ${join_seed:+--join "${join_seed}"} ${join_token:+--join-token "${join_token}"}
      fi
      echo "  改用本次会话内 nohup 常驻(重启机器/终端会话结束后不保留)。"
    fi
  fi

  local bin="${BINARY}"
  if [[ ! -x "${bin}" ]]; then
    local platform
    platform=$(detect_platform)
    if [[ -z "${version}" ]]; then
      version=$(get_latest_version)
      [[ -z "${version}" ]] && fail "无法获取最新版本,请用 --version 指定"
    fi
    echo "  本机未安装 rustio,下载 ${version}..."
    local new_bin
    new_bin=$(download_binary "${version}" "${platform}") || exit 1
    mkdir -p "${data_root}"
    bin="${data_root}/rustio"
    cp "${new_bin}" "${bin}"
    chmod +x "${bin}"
    rm -rf "$(dirname "${new_bin}")"
  fi

  mkdir -p "${data_root}/.pids"
  local internal_token
  # 加入已有集群时复用对方的 token——否则所有节点必须共享同一个 RUSTIO_INTERNAL_TOKEN 才能互相验证内部请求。
  if [[ -n "${join_token}" ]]; then
    internal_token="${join_token}"
  else
    internal_token="rustio-cluster-$(date +%s)-$$"
  fi
  local root_pass
  root_pass=$(gen_password)
  local jwt_secret
  jwt_secret=$(gen_password)

  local peer_map="" i port
  for ((i = 1; i <= num_nodes; i++)); do
    port=$((base_port + i - 1))
    [[ -n "${peer_map}" ]] && peer_map="${peer_map},"
    peer_map="${peer_map}meta-${i}=http://127.0.0.1:${port}"
  done
  # 把要加入的已有集群种子节点拼进 peer_map，让新节点 raft 启动时能识别为初始成员。
  if [[ -n "${join_seed}" ]]; then
    peer_map="${peer_map},${join_seed}"
  fi

  local nodes_conf="${data_root}/nodes.conf"
  : > "${nodes_conf}"

  for ((i = 1; i <= num_nodes; i++)); do
    port=$((base_port + i - 1))
    local node_dir="${data_root}/meta-${i}"
    mkdir -p "${node_dir}"
    echo "meta-${i}  127.0.0.1  ${port}  ${node_dir}  ${bin}" >> "${nodes_conf}"

    if [[ "${use_systemd}" == "1" ]]; then
      local env_file="/etc/rustio/env-meta-${i}"
      local service_file="/etc/systemd/system/rustio-meta-${i}.service"
      cat > "${env_file}" <<ENVEOF
RUSTIO_DATA_DIR=${node_dir}
RUSTIO_ADDR=:${port}
RUSTIO_ROOT_USER=rustioadmin
RUSTIO_ROOT_PASSWORD=${root_pass}
RUSTIO_CONSOLE_USER=admin
RUSTIO_CONSOLE_PASSWORD=${root_pass}
RUSTIO_JWT_SECRET=${jwt_secret}
RUSTIO_INTERNAL_TOKEN=${internal_token}
RUSTIO_METADATA_RAFT_NODE_ID=meta-${i}
RUSTIO_METADATA_RAFT_NETWORK_ENABLED=true
RUSTIO_METADATA_RAFT_PEERS=${peer_map}
RUST_LOG=info
ENVEOF
      chmod 600 "${env_file}"
      write_systemd_unit "${service_file}" "root" "${env_file}" "${bin}" "RustIO cluster node meta-${i}"
      systemctl daemon-reload
      systemctl enable "rustio-meta-${i}" >/dev/null 2>&1 || true
      systemctl restart "rustio-meta-${i}"
      echo "  ✅ meta-${i} 启动(systemd,端口 ${port})"
    else
      RUSTIO_DATA_DIR="${node_dir}" \
      RUSTIO_ADDR=":${port}" \
      RUSTIO_ROOT_USER="rustioadmin" \
      RUSTIO_ROOT_PASSWORD="${root_pass}" \
      RUSTIO_CONSOLE_USER="admin" \
      RUSTIO_CONSOLE_PASSWORD="${root_pass}" \
      RUSTIO_JWT_SECRET="${jwt_secret}" \
      RUSTIO_INTERNAL_TOKEN="${internal_token}" \
      RUSTIO_METADATA_RAFT_NODE_ID="meta-${i}" \
      RUSTIO_METADATA_RAFT_NETWORK_ENABLED="true" \
      RUSTIO_METADATA_RAFT_PEERS="${peer_map}" \
      RUST_LOG=error \
        nohup "${bin}" server "${node_dir}" --address ":${port}" \
        > "${data_root}/.pids/meta-${i}.log" 2>&1 &
      echo $! > "${data_root}/.pids/meta-${i}.pid"
      echo "  ✅ meta-${i} 启动(nohup,端口 ${port},PID $(cat "${data_root}/.pids/meta-${i}.pid"))"
    fi
  done

  echo ""
  echo "  等待集群选举..."
  local lid="" attempt
  for attempt in $(seq 1 30); do
    for ((i = 1; i <= num_nodes; i++)); do
      port=$((base_port + i - 1))
      lid=$(get_raft_leader "127.0.0.1" "${port}" "admin" "${root_pass}" || true)
      if [[ -n "${lid}" ]]; then
        echo "  ✅ Leader: ${lid}"
        break 2
      fi
    done
    sleep 2
  done

  echo ""
  echo "╔══════════════════════════════════════╗"
  echo "║   ✅ ${num_nodes} 节点本地集群部署完成       ║"
  echo "╚══════════════════════════════════════╝"
  echo ""
  if [[ "${use_systemd}" == "1" ]]; then
    echo "  持久化方式: systemd(开机自启)"
  else
    echo "  持久化方式: nohup(本次会话内常驻,不开机自启)"
  fi
  echo "  节点:"
  for ((i = 1; i <= num_nodes; i++)); do
    port=$((base_port + i - 1))
    echo "    meta-${i}  http://127.0.0.1:${port}"
  done
  echo "  用户: rustioadmin  密码: ${root_pass}"
  echo ""
  echo "  节点清单已写入: ${nodes_conf}(可直接用于滚动升级测试)"
  echo "    $0 upgrade --nodes ${nodes_conf} --dry-run --api-user admin --api-password ${root_pass}"
  echo ""
  echo "  停止集群:"
  echo "    $0 cluster --down --data ${data_root}"
}

cluster_down() {
  local data_root="$1"
  echo "=== 停止本地集群 ==="

  local -a systemd_units=()
  if compgen -G "/etc/systemd/system/rustio-meta-*.service" >/dev/null 2>&1; then
    systemd_units=(/etc/systemd/system/rustio-meta-*.service)
  fi

  if [[ ${#systemd_units[@]} -gt 0 && "$(id -u)" != "0" ]]; then
    echo "  检测到 systemd 集群服务,需要 root 权限清理。"
    exec sudo -E "$0" cluster --down --data "${data_root}"
  fi

  local svc
  for svc in "${systemd_units[@]+"${systemd_units[@]}"}"; do
    svc=$(basename "${svc}")
    echo "  停止 ${svc}..."
    timeout 30 systemctl stop "${svc}" 2>/dev/null || {
      echo "  ⚠️  正常停止超时,强制杀掉..."
      systemctl kill -s KILL "${svc}" 2>/dev/null || true
    }
    systemctl disable "${svc}" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}"
  done
  [[ ${#systemd_units[@]} -gt 0 ]] && { systemctl daemon-reload 2>/dev/null || true; }

  if [[ -d "${data_root}/.pids" ]]; then
    local pid_file pid
    for pid_file in "${data_root}"/.pids/*.pid; do
      [[ -f "${pid_file}" ]] || continue
      pid=$(cat "${pid_file}")
      if kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        sleep 1
        kill -9 "${pid}" 2>/dev/null || true
        echo "  ✅ 停止 $(basename "${pid_file}" .pid)(PID ${pid})"
      fi
      rm -f "${pid_file}"
    done
  fi

  echo "  ✅ 集群已停止(数据目录保留:${data_root})"
  echo "     如需彻底删除: rm -rf ${data_root}"
}

cmd_cluster() {
  local num_nodes=3
  local base_port=19801
  local data_root="${RUSTIO_CLUSTER_DATA:-${HOME}/.rustio/cluster}"
  local version="${RUSTIO_VERSION:-}"
  local down=0
  local join_seed=""  # 格式: node_id=http://host:port
  local join_token="" # 加入已有集群的内部通信令牌

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --nodes)      num_nodes="$2"; shift 2 ;;
      --base-port)  base_port="$2"; shift 2 ;;
      --data)       data_root="$2"; shift 2 ;;
      --version)    version="$2"; shift 2 ;;
      --join)       join_seed="$2"; shift 2 ;;
      --join-token) join_token="$2"; shift 2 ;;
      --down)       down=1; shift ;;
      --help|-h)
        echo "用法: $0 cluster [--nodes 3] [--base-port 19801] [--data <目录>] [--version vX]"
        echo "      $0 cluster --down [--data <目录>]"
        echo "      $0 cluster [选项] --join <node_id>=http://<host>:<port> [--join-token <token>]"
        echo "本地起 N 个节点组成 Raft 集群,用于测试/开发。有 systemd+root 时注册为持久化服务,"
        echo "否则用 nohup 常驻本次会话。默认数据目录 ~/.rustio/cluster。"
        echo "--join 指定把新节点加入已有集群(种子节点地址),--join-token 指定内部通信令牌,"
        echo "不写时从 /etc/rustio/env 自动获取(由 install 或 expand 子命令写入)。"
        return 0 ;;
      *) fail "未知参数: $1(cluster)" ;;
    esac
  done

  # 没有显式给 join-token 时,尝试从已有单机/env配置里提取。
  if [[ -z "${join_token}" && -n "${join_seed}" ]]; then
    if [[ -r "/etc/rustio/env" ]]; then
      join_token=$(grep '^RUSTIO_INTERNAL_TOKEN=' /etc/rustio/env 2>/dev/null | cut -d= -f2- || true)
    fi
    if [[ -z "${join_token}" ]]; then
      fail "--join 需要 --join-token,但未提供且未在 /etc/rustio/env 中找到 RUSTIO_INTERNAL_TOKEN。请用 expand 子命令先扩容单机,再 cluster --join。"
    fi
  fi

  if [[ "${down}" == "1" ]]; then
    cluster_down "${data_root}"
    return 0
  fi

  cluster_up "${num_nodes}" "${base_port}" "${data_root}" "${version}" "${join_seed}" "${join_token}"
}

# ── expand(把已有单机实例扩容为集群) ──

cmd_expand() {
  local -a peers=()
  local node_id="${RUSTIO_CLUSTER_NODE_ID:-1}"
  local node_addr="${RUSTIO_CLUSTER_NODE_ADDR:-}"
  local zone="${RUSTIO_CLUSTER_NODE_ZONE:-default}"
  local assume_yes=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --peer)    peers+=("$2"); shift 2 ;;
      --node-id) node_id="$2"; shift 2 ;;
      --addr)    node_addr="$2"; shift 2 ;;
      --zone)    zone="$2"; shift 2 ;;
      --yes)     assume_yes=1; shift ;;
      --help|-h)
        echo "用法: $0 expand --peer <node_id>=<host:port> [--peer ...] [--node-id 1] [--zone default] [--yes]"
        echo "把已用 install 部署好的单机实例就地扩容为集群第一个节点(需要重启 rustio 服务)。"
        echo "重启后按提示在新机器上执行给出的一键命令即可自动加入。"
        return 0 ;;
      *) fail "未知参数: $1(expand)" ;;
    esac
  done

  echo "=== RustIO 单机扩容为集群 ==="

  [[ "$(id -u)" == "0" ]] || fail "需要 root 权限,请用 sudo 运行。"
  [[ -r "${ENV_FILE}" ]] || fail "未找到 ${ENV_FILE},本机看起来不是用 install.sh install 部署的单机实例。"
  if grep -q '^RUSTIO_CLUSTER_NODE_ID=' "${ENV_FILE}" 2>/dev/null; then
    fail "当前实例已配置为集群节点(${ENV_FILE} 已有 RUSTIO_CLUSTER_NODE_ID),无需重复扩容。加节点请用控制台 IAM 或 POST /api/v1/cluster/membership/add。"
  fi
  if [[ ${#peers[@]} -eq 0 ]]; then
    fail "至少用 --peer <node_id>=<host:port> 指定一个要新增的节点"
  fi

  local current_addr
  current_addr=$(grep '^RUSTIO_ADDR=' "${ENV_FILE}" 2>/dev/null | cut -d= -f2- || true)
  local current_port="${current_addr##*:}"
  [[ -z "${current_port}" ]] && current_port=9000

  if [[ -z "${node_addr}" ]]; then
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [[ -z "${ip}" ]] && ip="127.0.0.1"
    node_addr="http://${ip}:${current_port}"
  fi

  local internal_token
  internal_token=$(grep '^RUSTIO_INTERNAL_TOKEN=' "${ENV_FILE}" 2>/dev/null | cut -d= -f2- || true)
  [[ -z "${internal_token}" ]] && internal_token=$(gen_password)

  local seeds="${node_id}=${node_addr}"
  local p
  for p in "${peers[@]}"; do
    seeds="${seeds},${p}"
  done

  echo "  本机节点 ID:   ${node_id}"
  echo "  本机对外地址:  ${node_addr}"
  echo "  新增 peer:     ${peers[*]}"
  echo "  完整 seeds:    ${seeds}"
  echo ""
  echo "  即将追加到 ${ENV_FILE} 并重启 rustio 服务(会短暂中断几秒,数据不受影响)。"

  if [[ "${assume_yes}" != "1" ]]; then
    local ans
    prompt ans "  确认继续? [y/N] " "N"
    if [[ ! "${ans}" =~ ^[Yy]$ ]]; then
      echo "  已取消"
      return 1
    fi
  fi

  {
    echo ""
    echo "# 由 install.sh expand 于 $(date -u +%Y-%m-%dT%H:%M:%SZ) 追加"
    echo "RUSTIO_CLUSTER_NODE_ID=${node_id}"
    echo "RUSTIO_CLUSTER_NODE_NAME=meta-${node_id}"
    echo "RUSTIO_CLUSTER_NODE_ADDR=${node_addr}"
    echo "RUSTIO_CLUSTER_NODE_ZONE=${zone}"
    echo "RUSTIO_CLUSTER_SEEDS=${seeds}"
    echo "RUSTIO_INTERNAL_TOKEN=${internal_token}"
    echo "RUSTIO_METADATA_RAFT_NETWORK_ENABLED=true"
    echo "RUSTIO_METADATA_RAFT_NODE_ID=meta-${node_id}"
    echo "RUSTIO_METADATA_RAFT_PEERS=${seeds}"
  } >> "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
  echo "  ✅ 已更新 ${ENV_FILE}"

  echo "  重启 rustio 服务..."
  systemctl restart rustio

  echo "  等待健康检查..."
  if wait_healthy "127.0.0.1" "${current_port}" 30; then
    echo "  ✅ 服务已恢复"
  else
    fail "服务未就绪,查看日志: journalctl -u rustio -n 30(配置已写入,可修正 ${ENV_FILE} 后重跑 systemctl restart rustio)"
  fi

  echo ""
  echo "=========================================="
  echo "  ✅ 已扩容为集群模式(node_id=${node_id})"
  echo "=========================================="
  echo ""
  echo "  在同一台机器或另一台机器上新增节点加入本集群:"
  echo ""
  echo "  # 方式一 · 全新安装节点并自动加入"
  echo "    curl -sSL https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh \\"
  echo "      | RUSTIO_CLUSTER_NODE_ID=2 RUSTIO_CLUSTER_SEEDS=${seeds} RUSTIO_INTERNAL_TOKEN=${internal_token} bash -s -- install"
  echo ""
  echo "  # 方式二 · 用 cluster 子命令本地起多个节点连上来"
  echo "    ${0} cluster --nodes 2 --base-port 19901 --join ${node_id}=${node_addr} --join-token ${internal_token}"
  echo ""
  echo "  # 方式三 · 手动安装二进制后,对应脚本里面设置好 RUSTIO_CLUSTER_NODE_ID/RUSTIO_CLUSTER_SEEDS/RUSTIO_INTERNAL_TOKEN 再启动"
  echo ""
  echo "  新节点启动后会自动发现并加入本集群,无需额外操作。"
}

# ── 交互菜单 ──

cmd_menu() {
  echo "╔══════════════════════════════════════╗"
  echo "║           RustIO 部署管理             ║"
  echo "╚══════════════════════════════════════╝"
  echo ""
  echo "  1) 安装(单机,自动装 systemd 服务)"
  echo "  2) 升级"
  echo "  3) 卸载"
  echo "  4) 本地多节点测试集群"
  echo "  5) 把已运行的手动进程接管为 systemd"
  echo "  6) 把已部署单机扩容为集群"
  echo "  0) 退出"
  echo ""
  local choice
  prompt choice "请选择操作 [0-6]: " "0"
  case "${choice}" in
    1)
      local version port data_dir
      prompt version "  版本(留空=最新): " ""
      prompt port "  端口 [9000]: " "9000"
      prompt data_dir "  数据目录 [/opt/rustio/data]: " "/opt/rustio/data"
      cmd_install ${version:+--version "${version}"} --port "${port}" --data "${data_dir}"
      ;;
    2)
      local nodes
      prompt nodes "  多节点配置文件(留空=单机): " ""
      if [[ -n "${nodes}" ]]; then
        cmd_upgrade --nodes "${nodes}"
      else
        cmd_upgrade
      fi
      ;;
    3)
      local purge_ans
      prompt purge_ans "  连同数据一起删除?不可恢复 [y/N]: " "N"
      if [[ "${purge_ans}" =~ ^[Yy]$ ]]; then
        cmd_uninstall --purge
      else
        cmd_uninstall
      fi
      ;;
    4)
      local n bp
      prompt n "  节点数 [3]: " "3"
      prompt bp "  起始端口 [19801]: " "19801"
      cmd_cluster --nodes "${n}" --base-port "${bp}"
      ;;
    5)
      local port
      prompt port "  端口 [9000]: " "9000"
      cmd_systemd --port "${port}"
      ;;
    6)
      echo "  扩容需要至少一个新节点信息,格式 node_id=host:port"
      local peer
      prompt peer "  新节点(如 2=http://10.0.0.2:9000): " ""
      if [[ -z "${peer}" ]]; then
        echo "  未输入,取消"
        return 1
      fi
      local yn
      prompt yn "  新节点在同一个机器上? [Y/n] " "Y"
      if [[ "${yn}" =~ ^[Yy]$ ]]; then
        echo "  同一台机器:用 cluster --join 在本机加更多节点。"
        local n bp
        prompt n "  新节点数 [2]: " "2"
        prompt bp "  起始端口 [19901]: " "19901"
        cmd_cluster --nodes "${n}" --base-port "${bp}" --join "${peer}"
      else
        cmd_expand --peer "${peer}"
      fi
      ;;
    0) echo "  已退出" ;;
    *) echo "  无效选项" ; return 1 ;;
  esac
}

# ── 主入口 ──

usage_main() {
  echo "RustIO 部署管理脚本"
  echo ""
  echo "用法:"
  echo "  $0                    有终端时进交互菜单,无终端(管道)时直接安装"
  echo "  $0 install [选项]     安装(默认最新版,自动装 systemd 服务)"
  echo "  $0 upgrade [选项]     升级(单机自动重启;--nodes <file> 走多节点滚动升级)"
  echo "  $0 uninstall [选项]   卸载"
  echo "  $0 systemd [选项]     把已运行的手动/nohup 进程接管为 systemd"
  echo "  $0 cluster [选项]     本地多节点测试集群(--down 停止)"
  echo "  $0 expand [选项]      把已部署的单机实例扩容为集群"
  echo "  $0 menu               强制进入交互菜单"
  echo "  $0 --help             显示本帮助"
  echo ""
  echo "子命令帮助: $0 <子命令> --help"
}

main() {
  local sub="${1:-}"
  case "${sub}" in
    install|upgrade|uninstall|systemd|cluster|expand|menu)
      shift
      "cmd_${sub}" "$@"
      ;;
    --help|-h)
      usage_main
      ;;
    "")
      if [[ -t 0 ]]; then
        cmd_menu
      else
        cmd_install
      fi
      ;;
    --*)
      cmd_install "$@"
      ;;
    *)
      echo "未知子命令: ${sub}" >&2
      usage_main
      exit 1
      ;;
  esac
}

main "$@"
