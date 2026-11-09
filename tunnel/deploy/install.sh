#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"
CFG_DIR="${CFG_DIR:-/etc/l2x-tunnel}"

echo "[l2x-tunnel] build in $ROOT"
cd "$ROOT"
if ! command -v go >/dev/null 2>&1; then
  echo "Go not found. Installing Go 1.22.x ..."
  curl -fsSL https://go.dev/dl/go1.22.10.linux-amd64.tar.gz -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
  export PATH="/usr/local/go/bin:$PATH"
fi
export PATH="/usr/local/go/bin:${PATH:-}"
go version
go mod tidy
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$PREFIX/bin/l2x-tunneld" ./cmd/l2x-tunneld
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$PREFIX/bin/l2x-tunnel-agent" ./cmd/l2x-tunnel-agent"

mkdir -p "$CFG_DIR"
if [[ ! -f "$CFG_DIR/tunneld.yaml" ]]; then
  cp deploy/tunneld.yaml "$CFG_DIR/tunneld.yaml"
fi
if [[ ! -f "$CFG_DIR/agent.yaml" ]]; then
  cp deploy/agent.yaml "$CFG_DIR/agent.yaml"
fi
cp deploy/l2x-tunneld.service /etc/systemd/system/
cp deploy/l2x-tunnel-agent.service /etc/systemd/system/
systemctl daemon-reload
echo "[l2x-tunnel] binaries in $PREFIX/bin — edit $CFG_DIR then: systemctl enable --now l2x-tunneld l2x-tunnel-agent"
