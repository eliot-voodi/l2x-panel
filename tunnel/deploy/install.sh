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
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$PREFIX/bin/l2x-tunnel-agent" ./cmd/l2x-tunnel-agent
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$PREFIX/bin/l2x-dnsd" ./cmd/l2x-dnsd

mkdir -p "$CFG_DIR" /etc/l2x-dnsd
if [[ ! -f "$CFG_DIR/tunneld.yaml" ]]; then
  cp deploy/tunneld.yaml "$CFG_DIR/tunneld.yaml"
fi
if [[ ! -f "$CFG_DIR/agent.yaml" ]]; then
  cp deploy/agent.yaml "$CFG_DIR/agent.yaml"
fi
if [[ ! -f /etc/l2x-dnsd/dnsd.yaml ]]; then
  cp deploy/dnsd.yaml /etc/l2x-dnsd/dnsd.yaml
fi
cp deploy/l2x-tunneld.service /etc/systemd/system/
cp deploy/l2x-tunnel-agent.service /etc/systemd/system/
cp deploy/l2x-dnsd.service /etc/systemd/system/
install -m 644 deploy/sysctl-perf.conf /etc/sysctl.d/99-l2xpanel-perf.conf
install -d /etc/modules-load.d
printf 'tcp_bbr\n' > /etc/modules-load.d/l2x-perf.conf
modprobe tcp_bbr 2>/dev/null || true
sysctl -e -p /etc/sysctl.d/99-l2xpanel-perf.conf >/dev/null || true
systemctl daemon-reload
echo "[l2x-tunnel] binaries in $PREFIX/bin — edit $CFG_DIR then: systemctl enable --now l2x-tunneld l2x-tunnel-agent"
