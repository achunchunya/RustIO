#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RUSTIO_ADDR="${RUSTIO_ADDR:-0.0.0.0:9000}"
RUSTIO_DATA_DIR="${RUSTIO_DATA_DIR:-$SCRIPT_DIR/data}"
RUSTIO_CONSOLE_DIST="${RUSTIO_CONSOLE_DIST:-$SCRIPT_DIR/web/console/dist}"
RUSTIO_AUTO_MIRROR="${RUSTIO_AUTO_MIRROR:-1}"
RUSTIO_USE_DOCKER_NODE_BUILD="${RUSTIO_USE_DOCKER_NODE_BUILD:-0}"
RUSTIO_SKIP_WEB_BUILD="${RUSTIO_SKIP_WEB_BUILD:-0}"

CURL_RETRY_ARGS=(
  --proto '=https'
  --tlsv1.2
  --fail
  --location
  --retry 3
  --retry-delay 2
  --connect-timeout 10
  --max-time 600
  --silent
  --show-error
)

log() {
  echo "[RustIO] $*"
}

fail() {
  echo "[RustIO] 错误：$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "未找到命令 $1，请先安装后重试。 / Command $1 not found, please install it first and retry."
}

curl_https() {
  curl "${CURL_RETRY_ARGS[@]}" "$@"
}

url_reachable() {
  curl --head --silent --output /dev/null --connect-timeout 3 --max-time 5 "$1"
}

get_rust_toolchain_channel() {
  if [[ -f "$SCRIPT_DIR/rust-toolchain.toml" ]]; then
    awk -F'"' '/^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }' "$SCRIPT_DIR/rust-toolchain.toml"
  fi
}

version_ge() {
  local current="$1"
  local required="$2"
  [[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n1)" == "$required" ]]
}

get_glibc_version() {
  if command -v getconf >/dev/null 2>&1; then
    getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}'
    return
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd --version 2>/dev/null | head -n1 | grep -Eo '[0-9]+\.[0-9]+' | head -n1
    return
  fi

  return 1
}

node_runtime_ok() {
  command -v node >/dev/null 2>&1 || return 1
  command -v npm >/dev/null 2>&1 || return 1
  node -v >/dev/null 2>&1 || return 1
  npm -v >/dev/null 2>&1 || return 1
}

enable_docker_node_build() {
  require_cmd docker
  RUSTIO_USE_DOCKER_NODE_BUILD=1
  log "检测到本机 Node.js 与系统运行库不兼容，改用 Docker 构建前端。"
}

configure_fast_mirrors() {
  export CARGO_REGISTRIES_CRATES_IO_PROTOCOL="${CARGO_REGISTRIES_CRATES_IO_PROTOCOL:-sparse}"

  if [[ "$RUSTIO_AUTO_MIRROR" != "1" ]]; then
    return
  fi

  local enabled=0

  if [[ -z "${RUSTUP_DIST_SERVER:-}" ]] && [[ -z "${RUSTUP_UPDATE_ROOT:-}" ]] && url_reachable "https://rsproxy.cn"; then
    export RUSTUP_DIST_SERVER="https://rsproxy.cn"
    export RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"
    enabled=1
  fi

  if [[ -z "${NVM_NODEJS_ORG_MIRROR:-}" ]] && url_reachable "https://npmmirror.com/mirrors/node"; then
    export NVM_NODEJS_ORG_MIRROR="https://npmmirror.com/mirrors/node"
    enabled=1
  fi

  if [[ -z "${RUSTIO_NPM_REGISTRY:-}" ]] && url_reachable "https://registry.npmmirror.com"; then
    export RUSTIO_NPM_REGISTRY="https://registry.npmmirror.com"
    enabled=1
  fi

  if (( enabled )); then
    log "检测到可用下载镜像，已启用加速。"
  fi
}

ensure_rust() {
  local rust_toolchain_channel=""

  rust_toolchain_channel="${RUSTIO_RUST_TOOLCHAIN:-$(get_rust_toolchain_channel || true)}"
  if [[ -z "$rust_toolchain_channel" ]]; then
    rust_toolchain_channel="stable"
  fi

  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    log "检测到 Rust 工具链：$(rustc -V)"
    return
  fi

  require_cmd curl
  configure_fast_mirrors
  log "未检测到 Rust，开始自动安装 rustup..."
  if [[ -n "${RUSTUP_DIST_SERVER:-}" ]]; then
    log "Rust 下载源：${RUSTUP_DIST_SERVER}"
  fi
  log "Rust 工具链版本：${rust_toolchain_channel}"
  log "如果此处长时间无输出，通常是下载源网络较慢，可稍后重试。"
  curl_https https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "${rust_toolchain_channel}"

  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  fi

  command -v cargo >/dev/null 2>&1 || fail "Rust 安装完成后仍未找到 cargo。"
  log "Rust 安装完成：$(rustc -V)"
}

ensure_nvm_loaded() {
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"

  if [[ -s "$NVM_DIR/nvm.sh" ]]; then
    # shellcheck disable=SC1090
    source "$NVM_DIR/nvm.sh"
    return 0
  fi

  return 1
}

ensure_node() {
  local node_major=""
  local glibc_version=""

  configure_fast_mirrors

  if node_runtime_ok; then
    node_major="$(node -p "process.versions.node.split('.')[0]")"
    if [[ "$node_major" =~ ^[0-9]+$ ]] && (( node_major >= 22 )); then
      log "检测到 Node.js：$(node -v)"
      return
    fi
  fi

  glibc_version="$(get_glibc_version || true)"
  if [[ -n "$glibc_version" ]] && ! version_ge "$glibc_version" "2.28"; then
    log "检测到系统 glibc 版本 ${glibc_version} 偏低，Node.js 22 可能无法直接运行。"
    enable_docker_node_build
    return
  fi

  require_cmd curl
  log "未检测到 Node.js 22+，开始通过 nvm 自动安装..."

  if ! ensure_nvm_loaded; then
    curl_https https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
    ensure_nvm_loaded || fail "nvm 安装后加载失败。"
  fi

  nvm install 22
  nvm alias default 22 >/dev/null
  nvm use 22 >/dev/null

  if node_runtime_ok; then
    log "Node.js 安装完成：$(node -v)"
    return
  fi

  log "本机 Node.js 仍无法运行，可能是系统 glibc 或 libstdc++ 版本过低。"
  enable_docker_node_build
}

ensure_build_toolchain() {
  if command -v cc >/dev/null 2>&1; then
    return
  fi

  case "$(uname -s)" in
    Darwin)
      fail "未找到 C 编译器。请先执行 xcode-select --install，然后重新运行脚本。 / C compiler not found. Please run xcode-select --install and retry."
      ;;
    Linux)
      fail "未找到 C 编译器。请先安装 build-essential 或 gcc，再重新运行脚本。 / C compiler not found. Please install build-essential or gcc and retry."
      ;;
    *)
      fail "当前系统缺少 C 编译器，请先安装后重试。 / C compiler is missing on this system, please install it and retry."
      ;;
  esac
}

build_console_locally() {
  log "开始构建控制台前端..."
  local npm_args=(ci --prefix web/console --prefer-offline --no-audit --no-fund)
  if [[ -n "${RUSTIO_NPM_REGISTRY:-}" ]]; then
    npm_args+=(--registry "${RUSTIO_NPM_REGISTRY}")
    log "NPM 下载源：${RUSTIO_NPM_REGISTRY}"
  fi
  npm "${npm_args[@]}"
  npm run build --prefix web/console
}

build_console_with_docker() {
  require_cmd docker
  mkdir -p "$SCRIPT_DIR/.cache/npm"
  log "开始使用 Docker 构建控制台前端..."

  docker run --rm \
    -v "$SCRIPT_DIR:/workspace" \
    -v "$SCRIPT_DIR/.cache/npm:/root/.npm" \
    -w /workspace/web/console \
    -e RUSTIO_NPM_REGISTRY="${RUSTIO_NPM_REGISTRY:-}" \
    node:22-alpine \
    sh -lc 'if [ -n "$RUSTIO_NPM_REGISTRY" ]; then npm ci --prefer-offline --no-audit --no-fund --registry "$RUSTIO_NPM_REGISTRY"; else npm ci --prefer-offline --no-audit --no-fund; fi && npm run build'
}

build_console() {
  if [[ "$RUSTIO_USE_DOCKER_NODE_BUILD" == "1" ]]; then
    build_console_with_docker
  else
    build_console_locally
  fi

  [[ -d "$RUSTIO_CONSOLE_DIST" ]] || fail "前端构建完成，但未找到静态目录：$RUSTIO_CONSOLE_DIST / Frontend build finished but dist directory was not found: $RUSTIO_CONSOLE_DIST"
}

build_backend() {
  log "开始构建后端..."
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL="${CARGO_REGISTRIES_CRATES_IO_PROTOCOL:-sparse}" \
    cargo build --release -p rustio
  [[ -x "$SCRIPT_DIR/target/release/rustio" ]] || fail "后端构建完成，但未找到可执行文件：$SCRIPT_DIR/target/release/rustio / Backend build finished but executable was not found: $SCRIPT_DIR/target/release/rustio"
}

run_rustio() {
  mkdir -p "$RUSTIO_DATA_DIR"
  log "启动 RustIO..."
  log "监听地址：$RUSTIO_ADDR"
  log "数据目录：$RUSTIO_DATA_DIR"
  log "控制台静态目录：$RUSTIO_CONSOLE_DIST"

  exec env \
    RUSTIO_ADDR="$RUSTIO_ADDR" \
    RUSTIO_DATA_DIR="$RUSTIO_DATA_DIR" \
    RUSTIO_CONSOLE_DIST="$RUSTIO_CONSOLE_DIST" \
    ./target/release/rustio
}

main() {
  ensure_rust

  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  fi

  ensure_build_toolchain

  if [[ "$RUSTIO_SKIP_WEB_BUILD" == "1" ]]; then
    log "已启用跳过前端构建，直接复用现有静态资源目录：$RUSTIO_CONSOLE_DIST"
    [[ -d "$RUSTIO_CONSOLE_DIST" ]] || fail "已启用跳过前端构建，但未找到静态目录：$RUSTIO_CONSOLE_DIST / Web build is skipped, but dist directory was not found: $RUSTIO_CONSOLE_DIST"
  else
    ensure_node
    build_console
  fi

  build_backend
  run_rustio
}

main "$@"
