#!/usr/bin/env bash
# 本地构建运行镜像（带代理、注入版本号），复用固定 build-arg 组合以命中 layer cache。
#
# 用法：
#   ./scripts/build-image.sh <版本号> [镜像名]
#   例：./scripts/build-image.sh 0.3.20 tomicdd/artex
#
# 为什么要这个脚本：
#   1) Dockerfile 只 COPY 预编译二进制（dist/<arch>/artex），**不编译**——必须先建二进制，
#      否则镜像里还是上一版代码。
#   2) 本地访问 GitHub/PyPI 受限、deb.debian.org 直连极慢，必须走宿主机代理。
#   3) build-arg 组合一变，从声明该 ARG 的那层起缓存全失效。固定用同一组参数才不会
#      每次都重下整个 apt 层。
set -euo pipefail

VER="${1:?用法: $0 <版本号> [镜像名]}"
IMAGE="${2:-tomicdd/artex}"
PROXY="${BUILD_PROXY:-http://192.168.10.7:7890}"
PIP_INDEX="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
ARCH="${ARCH:-amd64}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH=/data/tools/go/bin:$PATH
export GOMODCACHE=/data/tools/gomodcache GOCACHE=/data/tools/gocache

echo "== 1/3 前端静态产物（web/out → server/webui/dist）"
if [ ! -f server/webui/dist/index.html ]; then
  (cd web && npm run build:static)
  rm -rf server/webui/dist && mkdir -p server/webui/dist && cp -r web/out/. server/webui/dist/
fi

echo "== 2/3 后端二进制（-X main.version=$VER）"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -tags embedui -trimpath \
  -ldflags "-s -w -X main.version=$VER" -o "dist/$ARCH/artex" ./cmd/artex
python3 - "$VER" "dist/$ARCH/artex" <<'PY'
import sys
ver, path = sys.argv[1], sys.argv[2]
d = open(path, 'rb').read()
print(f"   二进制 {len(d)} 字节，版本串 {ver} 出现 {d.count(ver.encode())} 次")
PY

echo "== 3/3 docker build -t $IMAGE:$VER"
docker build \
  --build-arg HTTP_PROXY="$PROXY" \
  --build-arg HTTPS_PROXY="$PROXY" \
  --build-arg PIP_INDEX_URL="$PIP_INDEX" \
  -t "$IMAGE:$VER" .
echo "完成：$IMAGE:$VER"