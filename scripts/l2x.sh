#!/usr/bin/env bash
# L2X Panel — server CLI menu (install as /usr/local/bin/l2x)
set -u
APP_DIR=${APP_DIR:-/opt/l2xpanel}
DATA=${L2XPANEL_DATA:-/var/lib/l2xpanel}
ENV_FILE=/etc/l2xpanel/panel.env
INSTALL_URL=${L2X_INSTALL_URL:-https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh}
PY="$APP_DIR/.venv/bin/python"
[ -x "$PY" ] || PY=python3

c_ok() { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
c_err() { printf '\033[31m%s\033[0m\n' "$*"; }
c_head() { printf '\n\033[36m%s\033[0m\n' "$*"; }

need_root() { [ "$(id -u)" = 0 ] || { c_err "Запустите от root (sudo l2x)"; exit 1; }; }

pyrun() {
  L2XPANEL_DATA="$DATA" "$PY" - "$@"
}

store_get() {
  pyrun "$1" <<'EOF'
import json, os, sys
s = json.load(open(os.path.join(os.environ["L2XPANEL_DATA"], "store.json"), encoding="utf-8"))
cur = s
for k in sys.argv[1].split("."):
    cur = (cur or {}).get(k) if isinstance(cur, dict) else None
print("" if cur is None else cur)
EOF
}

store_set() {
  pyrun "$1" "$2" <<'EOF'
import json, os, sys
p = os.path.join(os.environ["L2XPANEL_DATA"], "store.json")
s = json.load(open(p, encoding="utf-8"))
keys = sys.argv[1].split(".")
cur = s
for k in keys[:-1]:
    cur = cur.setdefault(k, {})
val = sys.argv[2]
cur[keys[-1]] = {"true": True, "false": False}.get(val, val)
tmp = p + ".tmp"
json.dump(s, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
os.replace(tmp, p)
EOF
}

public_ip() {
  local h
  h=$(store_get settings.panel.public_host 2>/dev/null)
  [ -n "$h" ] || h=$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
  echo "$h"
}

panel_url() {
  local bp h scheme=https
  bp=$(store_get settings.panel.base_path 2>/dev/null)
  h=$(public_ip)
  [[ $h =~ ^[0-9.]+$ || $h == *:* ]] && scheme=http
  echo "$scheme://$h/${bp:+$bp/}"
}

run_installer() {
  bash <(curl -fsSL "$INSTALL_URL") "$@"
}

show_status() {
  c_head "Статус"
  for u in l2xpanel xray nginx caddy xl2tpd strongswan-starter ipsec; do
    systemctl list-unit-files "$u.service" >/dev/null 2>&1 || continue
    st=$(systemctl is-active "$u" 2>/dev/null)
    [ -z "$st" ] && continue
    if [ "$st" = active ]; then c_ok "  $u: $st"; else c_warn "  $u: $st"; fi
  done
  echo "  Xray: $(/usr/local/bin/xray version 2>/dev/null | head -1)"
  echo "  Панель: $(panel_url)"
  echo "  Админ: $("$PY" -c "import json;print(json.load(open('$DATA/admin.json'))['username'])" 2>/dev/null)"
  echo "  BBR: $(sysctl -n net.ipv4.tcp_congestion_control)"
  echo "  Аптайм: $(uptime -p)"
}

reset_password() {
  read -r -p "Новый логин [admin]: " u; u=${u:-admin}
  read -r -s -p "Новый пароль (мин. 8): " p; echo
  [ ${#p} -ge 8 ] || { c_err "Слишком короткий"; return; }
  pyrun "$u" "$p" <<'EOF'
import bcrypt, json, os, sys
p = os.path.join(os.environ["L2XPANEL_DATA"], "admin.json")
json.dump({"username": sys.argv[1], "password_hash": bcrypt.hashpw(sys.argv[2].encode(), bcrypt.gensalt()).decode()}, open(p, "w"))
os.chmod(p, 0o600)
EOF
  c_ok "Логин/пароль обновлены"
}

disable_2fa() {
  store_set settings.security.totp_enabled false && store_set settings.security.totp_secret "" && systemctl restart l2xpanel && c_ok "2FA отключена"
}

reset_base_path() {
  local bp
  bp=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
  store_set settings.panel.base_path "$bp" && systemctl restart l2xpanel && sleep 3 && c_ok "Новый секретный путь: $(panel_url)"
}

issue_ssl() {
  read -r -p "Домен: " d; [ -n "$d" ] || return
  read -r -p "Email (необязательно): " e
  pyrun "$d" "$e" <<'EOF'
import sys
sys.path.insert(0, "/opt/l2xpanel")
import ops
r = ops.issue_cert(sys.argv[1], sys.argv[2])
print(r.get("log", "")[-3000:])
print("OK" if r.get("ok") else "ERROR: " + str(r.get("error")), r.get("cert_file", ""), r.get("key_file", ""))
EOF
}

toggle_bbr() {
  if [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = bbr ]; then
    printf 'net.core.default_qdisc=fq_codel\nnet.ipv4.tcp_congestion_control=cubic\n' > /etc/sysctl.d/99-l2x-bbr.conf
  else
    printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > /etc/sysctl.d/99-l2x-bbr.conf
  fi
  sysctl -p /etc/sysctl.d/99-l2x-bbr.conf && c_ok "Теперь: $(sysctl -n net.ipv4.tcp_congestion_control)"
}

firewall() {
  c_head "Открытые порты INPUT (iptables)"
  iptables -S INPUT | grep -E 'dport|ACCEPT' | head -40
  read -r -p "Открыть TCP/UDP порт (пусто — пропустить): " port
  if [ -n "$port" ] && pyrun "$port" <<'EOF'
import json, os, sys
s = json.load(open(os.path.join(os.environ["L2XPANEL_DATA"], "store.json"), encoding="utf-8"))
sys.exit(0 if int(sys.argv[1]) in {int(i.get("port") or 0) for i in s.get("inbounds") or []} else 1)
EOF
  then
    c_err "Порт $port занят inbound: inbounds доступны только через nginx :443, их порты закрыты снаружи"
    return
  fi
  if [ -n "$port" ]; then
    for proto in tcp udp; do
      iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT
    done
    command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1
    c_ok "Порт $port открыт"
  fi
}

speedtest() {
  c_head "Скачивание 50 МБ с Cloudflare"
  curl -o /dev/null -s -w 'Скорость: %{speed_download} байт/с (%{time_total} с)\n' "https://speed.cloudflare.com/__down?bytes=50000000"
}

geo_update() {
  pyrun <<'EOF'
import sys
sys.path.insert(0, "/opt/l2xpanel")
import ops
r = ops.update_geo([])
print(r.get("log"))
EOF
  systemctl restart xray && c_ok "Xray перезапущен"
}

backup() {
  f="/root/l2xpanel-$(date +%Y%m%d-%H%M).zip"
  pyrun "$f" <<'EOF'
import os, sys
from pathlib import Path
sys.path.insert(0, "/opt/l2xpanel")
import ops
open(sys.argv[1], "wb").write(ops.make_backup(Path(os.environ["L2XPANEL_DATA"])))
EOF
  c_ok "Бэкап: $f"
}

logs() {
  read -r -p "Сервис [l2xpanel/xray/xl2tpd] (xray): " u
  journalctl -u "${u:-xray}" -n 200 --no-pager
}

menu() {
  cat <<EOF

  ╭──────────────────────────────────╮
  │        L2X Panel · CLI           │
  ╰──────────────────────────────────╯
   1) Статус
   2) Перезапустить панель
   3) Перезапустить Xray
   4) Показать адрес панели
   5) Сбросить логин/пароль админа
   6) Отключить 2FA
   7) Новый секретный путь панели
   8) Выпустить SSL (Let's Encrypt)
   9) Вкл/выкл BBR
  10) Firewall: открыть порт
  11) Speedtest
  12) Обновить geoip/geosite
  13) Бэкап в /root
  14) Логи
  15) Обновить панель
  16) Удалить панель
   0) Выход
EOF
  read -r -p "Выбор: " ch
  case "$ch" in
    1) show_status ;;
    2) systemctl restart l2xpanel && c_ok "Панель перезапущена" ;;
    3) systemctl restart xray && c_ok "Xray перезапущен" ;;
    4) echo "$(panel_url)" ;;
    5) reset_password ;;
    6) disable_2fa ;;
    7) reset_base_path ;;
    8) issue_ssl ;;
    9) toggle_bbr ;;
    10) firewall ;;
    11) speedtest ;;
    12) geo_update ;;
    13) backup ;;
    14) logs ;;
    15) run_installer --update ;;
    16) run_installer --uninstall; exit 0 ;;
    0|q) exit 0 ;;
    *) c_warn "Неизвестный пункт" ;;
  esac
}

need_root
case "${1:-}" in
  status) show_status ;;
  restart) systemctl restart l2xpanel xray && c_ok "ok" ;;
  url) panel_url ;;
  reset-password) reset_password ;;
  disable-2fa) disable_2fa ;;
  reset-path) reset_base_path ;;
  backup) backup ;;
  update) run_installer --update ;;
  uninstall) run_installer --uninstall ;;
  "") while true; do menu; done ;;
  *) echo "Использование: l2x [status|restart|url|reset-password|disable-2fa|reset-path|backup|update|uninstall]" ;;
esac
