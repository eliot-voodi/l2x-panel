#!/bin/sh
set -e
mkdir -p "$L2XPANEL_DATA" "$L2XPANEL_DATA/ipsec" "$L2XPANEL_DATA/l2tp" /etc/l2xpanel/certs /etc/xray \
  /var/log/xray /var/log/supervisor /var/run/xl2tpd /etc/ppp

for m in ppp_generic l2tp_ppp l2tp_netlink pppol2tp af_key xfrm_user; do modprobe "$m" 2>/dev/null || true; done
[ -e /dev/ppp ] || mknod /dev/ppp c 108 0 2>/dev/null || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

[ -f /etc/ipsec.secrets ] || install -m 600 /dev/null /etc/ipsec.secrets
if [ ! -s /etc/xray/config.json ]; then
  cat > /etc/xray/config.json <<'EOF'
{"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]}
EOF
fi
echo "L2X Panel: http://<IP>:${PANEL_PORT}/  (login ${PANEL_ADMIN_USER:-admin})"
echo "On first start a random admin password is printed below and saved to \$L2XPANEL_DATA/initial_credentials.txt"
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
