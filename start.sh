#!/usr/bin/env bash

set -euo pipefail

probe_docker_api_compatibility() {
  local probe_output=""
  local probe_status=0
  local supported_api_version=""

  set +e
  probe_output="$(docker version --format '{{.Server.APIVersion}}' 2>&1)"
  probe_status=$?
  set -e

  if [[ $probe_status -eq 0 ]]; then
    return 0
  fi

  supported_api_version="$(
    printf '%s\n' "$probe_output" \
      | sed -nE 's/.*Maximum supported API version is ([0-9.]+).*/\1/p' \
      | head -n1
  )"

  if [[ -n "$supported_api_version" ]]; then
    export DOCKER_API_VERSION="$supported_api_version"
    echo "检测到 Docker Daemon 最大 API 版本为 ${supported_api_version}，已自动启用兼容模式。 / Detected Docker daemon max API version ${supported_api_version}; enabling compatibility mode."
    if docker version --format '{{.Server.APIVersion}}' >/dev/null 2>&1; then
      return 0
    fi
    echo "错误: 自动切换 Docker API 兼容模式后仍无法连接 daemon。 / Failed to connect to Docker daemon after enabling compatibility mode." >&2
  else
    echo "错误: 检测 Docker daemon 版本失败。 / Failed to detect Docker daemon API version." >&2
  fi

  printf '%s\n' "$probe_output" >&2
  exit 1
}

if ! command -v docker >/dev/null 2>&1; then
  echo "错误: 未找到 docker，请先安装 Docker Desktop 或 Docker Engine。"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "错误: 当前 docker 环境未启用 compose 插件。"
  exit 1
fi

probe_docker_api_compatibility

echo "使用 Docker 一键启动 RustIO（单端口模式，9000 同时提供 API 与管理端）..."

compose_args=(up)

case "${1:-}" in
  "")
    ;;
  --build|--rebuild)
    compose_args+=(--build)
    echo "检测到 --build，正在强制重建镜像。 / Detected --build, forcing image rebuild."
    ;;
  *)
    echo "用法: ./start.sh [--build] / Usage: ./start.sh [--build]"
    exit 1
    ;;
esac

docker compose "${compose_args[@]}"
