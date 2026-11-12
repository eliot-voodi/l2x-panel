#!/bin/sh
set -e
mkdir -p "$L2XPANEL_DATA" /etc/l2xpanel/certs /etc/xray \
  /var/log/xray /var/log/supervisor

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

if [ ! -s /etc/xray/config.json ]; then
  cat > /etc/xray/config.json <<'EOF'
{"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]}
EOF
fi
echo "L2X Panel: http://<IP>:${PANEL_PORT}/  (login ${PANEL_ADMIN_USER:-admin})"
echo "On first start a random admin password is printed below and saved to \$L2XPANEL_DATA/initial_credentials.txt"
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
