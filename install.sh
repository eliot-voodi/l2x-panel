#!/usr/bin/env bash
# L2X Panel — interactive installer for Debian 12+ / Ubuntu 22.04+
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh)
#
# On an installed server the same command opens a menu: update / reinstall code / uninstall.
#
# Flags:
#   --yes, -y     non-interactive: take answers from the environment or defaults
#   --update      update code, keep data and settings
#   --uninstall   remove services and code (data in /var/lib/l2xpanel is kept)
#
# Environment (non-interactive answers):
#   L2X_HOST      public IP or domain           (default: detected IPv4)
#   L2X_ADMIN     admin login                   (default: admin)
#   L2X_PASSWORD  admin password                (default: random)
#   L2X_PATH      secret panel path, "-" = none (default: random)
#   L2X_MODE      nginx | direct                (default: nginx — panel on :80 behind nginx)
#   L2X_PORT      panel port for direct mode    (default: 2053)
#   L2X_SSL       ip | domain | none            (default: none) Let's Encrypt for HTTPS subscriptions
#   L2X_DOMAIN    domain for L2X_SSL=domain
#   L2X_EMAIL     e-mail for Let's Encrypt      (optional)
#   XRAY_VERSION  Xray-core tag, e.g. v26.10.31 (default: latest)
#   L2X_REPO, L2X_BRANCH  source repository     (default: eliot-voodi/l2x-panel, main)
set -euo pipefail

REPO_URL=${L2X_REPO:-https://github.com/eliot-voodi/l2x-panel}
BRANCH=${L2X_BRANCH:-main}
APP_DIR=/opt/l2xpanel
DATA_DIR=/var/lib/l2xpanel
ETC_DIR=/etc/l2xpanel
ENV_FILE=$ETC_DIR/panel.env
XRAY_BIN=/usr/local/bin/xray
GEO_DIR=/usr/local/share/xray
ACME_WEBROOT=/var/www/l2x-acme
NGINX_SITE=/etc/nginx/sites-available/l2xpanel.conf
SUB_PORT=2096
PANEL_TLS_PORT=2053

# ---------------------------------------------------------------- ui helpers
if [ -t 1 ]; then
  R=$'\033[31m' G=$'\033[32m' Y=$'\033[33m' B=$'\033[36m' W=$'\033[1m' N=$'\033[0m'
else
  R='' G='' Y='' B='' W='' N=''
fi
ok()   { printf '%s✔%s %s\n' "$G" "$N" "$*"; }
info() { printf '%s➜%s %s\n' "$B" "$N" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%s✖ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }
step() { printf '\n%s%s%s\n' "$W" "$*" "$N"; }

INTERACTIVE=1
for a in "$@"; do case "$a" in -y|--yes) INTERACTIVE=0 ;; esac; done
if [ "$INTERACTIVE" = 1 ] && ! (exec </dev/tty) 2>/dev/null; then INTERACTIVE=0; fi

# ask VAR "question" "default"
ask() {
  local __var=$1 __q=$2 __def=${3:-} __a=""
  if [ "$INTERACTIVE" = 1 ]; then
    printf '%s?%s %s%s: ' "$B" "$N" "$__q" "${__def:+ ${W}[$__def]${N}}" >/dev/tty
    IFS= read -r __a </dev/tty || true
  fi
  printf -v "$__var" '%s' "${__a:-$__def}"
}

# choose VAR "question" default "1|label" "2|label" ...
choose() {
  local __var=$1 __q=$2 __def=$3 __a="" __opt
  shift 3
  if [ "$INTERACTIVE" = 1 ]; then
    printf '%s?%s %s\n' "$B" "$N" "$__q" >/dev/tty
    for __opt in "$@"; do printf '    %s%s)%s %s\n' "$W" "${__opt%%|*}" "$N" "${__opt#*|}" >/dev/tty; done
    while :; do
      printf '  Выбор %s[%s]%s: ' "$W" "$__def" "$N" >/dev/tty
      IFS= read -r __a </dev/tty || true
      __a=${__a:-$__def}
      for __opt in "$@"; do [ "${__opt%%|*}" = "$__a" ] && break 2; done
      warn "Нет такого пункта" >/dev/tty
    done
  fi
  printf -v "$__var" '%s' "${__a:-$__def}"
}

confirm() {
  local __yn
  ask __yn "$1 (y/n)" "${2:-y}"
  [[ $__yn =~ ^[YyДд] ]]
}

rand() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1" || true; }
is_ip() { [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || $1 == *:* ]]; }

banner() {
  printf '%s' "$B"
  cat <<'EOF'

   ██╗     ██████╗ ██╗  ██╗    ██████╗  █████╗ ███╗   ██╗███████╗██╗
   ██║     ╚════██╗╚██╗██╔╝    ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║
   ██║      █████╔╝ ╚███╔╝     ██████╔╝███████║██╔██╗ ██║█████╗  ██║
   ██║     ██╔═══╝  ██╔██╗     ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║
   ███████╗███████╗██╔╝ ██╗    ██║     ██║  ██║██║ ╚████║███████╗███████╗
   ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
EOF
  printf '%s        Xray-core + multi-L2TP · VLESS / VMess / Trojan / SS / Hysteria2%s\n\n' "$N" "$N"
}

# ---------------------------------------------------------------- checks
[ "$(id -u)" = 0 ] || die "Запустите от root: sudo bash install.sh"
[ -r /etc/os-release ] && . /etc/os-release
case "${ID:-}${ID_LIKE:-}" in
  *debian*|*ubuntu*) ;;
  *) warn "Проверено только на Debian/Ubuntu (у вас: ${PRETTY_NAME:-unknown})" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) XRAY_ASSET=Xray-linux-64.zip ;;
  aarch64|arm64) XRAY_ASSET=Xray-linux-arm64-v8a.zip ;;
  armv7*) XRAY_ASSET=Xray-linux-arm32-v7a.zip ;;
  *) die "Архитектура не поддерживается: $(uname -m)" ;;
esac

# ---------------------------------------------------------------- actions
fetch_source() {
  SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)
  if [ -f "$SCRIPT_DIR/panel/app.py" ]; then
    SRC=$SCRIPT_DIR
    return
  fi
  command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null; }
  SRC=$(mktemp -d)
  trap 'rm -rf "$SRC"' EXIT
  info "Загрузка $REPO_URL ($BRANCH)"
  curl -fsSL "$REPO_URL/archive/$BRANCH.tar.gz" | tar -xz -C "$SRC" --strip-components=1
  [ -f "$SRC/panel/app.py" ] || die "В архиве нет panel/app.py"
}

install_packages() {
  step "Пакеты"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    curl ca-certificates unzip jq openssl socat cron kmod iproute2 iptables \
    python3 python3-venv \
    ppp xl2tpd strongswan strongswan-starter libstrongswan-standard-plugins wireguard-tools >/dev/null
  ok "Системные пакеты"
  # nginx is always the public entry: :443 front for inbounds (Xray listens only on 127.0.0.1)
  if systemctl is-active -q caddy 2>/dev/null; then
    warn "Caddy занимает :80/:443 — останавливаю и отключаю его"
    systemctl disable --now caddy
  fi
  apt-get install -y -qq nginx libnginx-mod-stream >/dev/null
  ok "$(nginx -v 2>&1 | sed 's/.*: //') + stream"
}

install_xray() {
  step "Xray-core"
  if [ -x "$XRAY_BIN" ] && [ -z "${XRAY_VERSION:-}" ]; then
    ok "Уже установлен: $("$XRAY_BIN" version | head -1 | awk '{print $2}')"
  else
    local ver=${XRAY_VERSION:-latest} tmp
    [ "$ver" = latest ] && ver=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    info "Загрузка Xray-core $ver"
    tmp=$(mktemp -d)
    curl -fsSL -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/$ver/$XRAY_ASSET"
    unzip -qo "$tmp/xray.zip" -d "$tmp"
    install -m 755 "$tmp/xray" "$XRAY_BIN"
    mkdir -p "$GEO_DIR"
    install -m 644 "$tmp"/*.dat "$GEO_DIR/"
    rm -rf "$tmp"
    ok "$("$XRAY_BIN" version | head -1)"
  fi
  mkdir -p /etc/xray /var/log/xray
  [ -s /etc/xray/config.json ] || cat > /etc/xray/config.json <<'EOF'
{"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]}
EOF
}

install_code() {
  step "Панель"
  mkdir -p "$APP_DIR" "$DATA_DIR" "$ETC_DIR/certs"
  chmod 700 "$DATA_DIR" "$ETC_DIR"
  rm -rf "$APP_DIR/ui" "$APP_DIR"/*.py
  cp -a "$SRC/panel/." "$APP_DIR/"
  find "$APP_DIR" -name '__pycache__' -prune -exec rm -rf {} +
  if [ ! -x "$APP_DIR/.venv/bin/uvicorn" ]; then
    python3 -m venv "$APP_DIR/.venv"
    "$APP_DIR/.venv/bin/pip" install -q --upgrade pip
  fi
  "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
  install -m 755 "$SRC/scripts/l2x.sh" /usr/local/bin/l2x
  ok "Код в $APP_DIR, данные в $DATA_DIR"
}

backup_unmanaged() {
  if [ -f "$1" ] && ! grep -q 'managed by l2x-panel' "$1"; then
    cp -a "$1" "$1.bak-$(date +%Y%m%d%H%M%S)"
    warn "Сохранена копия $1"
  fi
}

install_system() {
  step "Системная настройка"
  install -m 644 "$SRC/deploy/sysctl.conf" /etc/sysctl.d/99-l2xpanel.conf
  sysctl -q -p /etc/sysctl.d/99-l2xpanel.conf >/dev/null || true
  install -m 644 "$SRC/deploy/modules.conf" /etc/modules-load.d/l2xpanel.conf
  while read -r mod; do modprobe "$mod" 2>/dev/null || true; done < "$SRC/deploy/modules.conf"

  backup_unmanaged /etc/ipsec.conf
  install -m 644 "$SRC/deploy/ipsec.conf" /etc/ipsec.conf
  [ -f /etc/ipsec.secrets ] || install -m 600 /dev/null /etc/ipsec.secrets
  mkdir -p /etc/xl2tpd /var/run/xl2tpd "$DATA_DIR/ipsec" "$DATA_DIR/l2tp"
  if ! grep -q 'managed by l2x-panel' /etc/xl2tpd/xl2tpd.conf 2>/dev/null; then
    backup_unmanaged /etc/xl2tpd/xl2tpd.conf
    install -m 644 "$SRC/deploy/xl2tpd.conf" /etc/xl2tpd/xl2tpd.conf
  fi

  install -m 644 "$SRC/deploy/xray.service" /etc/systemd/system/xray.service
  install -m 644 "$SRC/deploy/l2xpanel.service" /etc/systemd/system/l2xpanel.service
  systemctl daemon-reload
  systemctl enable -q strongswan-starter xl2tpd xray l2xpanel 2>/dev/null || true
  systemctl restart strongswan-starter xl2tpd 2>/dev/null || warn "strongSwan/xl2tpd не запустились — L2TP-туннели будут недоступны"

  mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge" /etc/nginx/l2x
  if [ "$MODE" = nginx ]; then
    install -m 644 "$SRC/deploy/nginx.conf" "$NGINX_SITE"
  else
    install -m 644 "$SRC/deploy/nginx-acme.conf" "$NGINX_SITE"
  fi
  ln -sfn "$NGINX_SITE" /etc/nginx/sites-enabled/l2xpanel.conf
  rm -f /etc/nginx/sites-enabled/default
  nginx -t -q 2>/dev/null || die "Ошибка конфигурации nginx: nginx -t"
  systemctl enable -q nginx
  systemctl restart nginx
  ok "systemd, sysctl, strongSwan, xl2tpd, nginx ($MODE)"
}

write_env() {
  local bind=127.0.0.1 port=8090 key
  [ "$MODE" = direct ] && { bind=0.0.0.0; port=$PANEL_PORT; }
  # reuse the key of a previous install: it encrypts stored L2TP secrets and signs sessions
  key=$(sed -n 's/^SECRET_KEY=//p' "$ENV_FILE" 2>/dev/null || true)
  [ -n "$key" ] || key=$(cat "$DATA_DIR/secret_key" 2>/dev/null || true)
  [ -n "$key" ] || key=$(openssl rand -hex 32)
  cat > "$ENV_FILE" <<EOF
APP_NAME="L2X Panel"
PANEL_ADMIN_USER=$ADMIN_USER
PANEL_ADMIN_PASSWORD=$ADMIN_PASSWORD
SECRET_KEY=$key
L2XPANEL_PUBLIC_HOST=$PUBLIC_HOST
L2XPANEL_DATA=$DATA_DIR
XRAY_BIN=$XRAY_BIN
XRAY_CONFIG=/etc/xray/config.json
XRAY_LOCATION_ASSET=$GEO_DIR
HOST=$bind
PORT=$port
EOF
  chmod 600 "$ENV_FILE"
  # the panel creates admin.json from PANEL_ADMIN_* only when it is missing
  rm -f "$DATA_DIR/admin.json"
  python3 - "$DATA_DIR/store.json" "$PANEL_PATH" "$PUBLIC_HOST" <<'EOF'
import json, os, sys
path, base_path, host = sys.argv[1:4]
try:
    d = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError):
    d = {}
d.setdefault("settings", {}).setdefault("panel", {}).update({"base_path": base_path, "public_host": host})
tmp = path + ".tmp"
json.dump(d, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
os.replace(tmp, path)
os.chmod(path, 0o600)
EOF
}

scrub_env_password() {
  # admin.json already holds the hash; drop the plaintext from panel.env
  [ -f "$ENV_FILE" ] || return 0
  grep -v '^PANEL_ADMIN_PASSWORD=' "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

wait_panel() {
  local port
  port=$(sed -n 's/^PORT=//p' "$ENV_FILE")
  systemctl restart xray l2xpanel
  for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:${port:-8090}/health" >/dev/null 2>&1; then
      scrub_env_password
      return 0
    fi
    sleep 1
  done
  die "Панель не запустилась: journalctl -u l2xpanel -n 50"
}

py() { (cd "$APP_DIR" && set -a && . "$ENV_FILE" && set +a && HOME=/root "$APP_DIR/.venv/bin/python" - "$@"); }

setup_ssl() {
  [ "$SSL" = none ] && return 0
  local name=$PUBLIC_HOST
  [ "$SSL" = domain ] && name=$SSL_DOMAIN
  step "Сертификат Let's Encrypt для $name"
  info "Проверка через порт 80 — он должен быть открыт снаружи"
  local out
  out=$(py "$name" "$SSL_EMAIL" <<'EOF'
import sys
import ops
r = ops.issue_cert(sys.argv[1], sys.argv[2])
print(r.get("log", "")[-1500:], file=sys.stderr)
print("OK" if r.get("ok") else "FAIL", r.get("cert_file", ""), r.get("key_file", ""), r.get("error", ""))
EOF
) || true
  set -- $out
  if [ "${1:-}" != OK ]; then
    warn "Сертификат не выпущен (${*:2}). Повторите позже: панель → Настройки → Сертификаты"
    SSL=none
    return 0
  fi
  CERT_FILE=$2 KEY_FILE=$3
  systemctl stop l2xpanel
  py "$name" "$CERT_FILE" "$KEY_FILE" "$MODE" "$SUB_PORT" "$PANEL_TLS_PORT" <<'EOF'
import json, os, sys
name, crt, key, mode, sub_port, tls_port = sys.argv[1:7]
p = os.path.join(os.environ["L2XPANEL_DATA"], "store.json")
d = json.load(open(p, encoding="utf-8"))
s = d.setdefault("settings", {})
s.setdefault("sub", {}).update({"server_enabled": True, "listen": "0.0.0.0", "port": int(sub_port),
                                "domain": name, "cert_file": crt, "key_file": key})
if mode == "nginx":
    s.setdefault("panel", {})["extra_listen"] = {"enabled": True, "port": int(tls_port), "cert_file": crt, "key_file": key}
tmp = p + ".tmp"
json.dump(d, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
os.replace(tmp, p)
EOF
  ok "Сертификат: $CERT_FILE (автопродление acme.sh)"
}

open_firewall() {
  command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active' || return 0
  local ports="22/tcp 443/tcp"
  if [ "$MODE" = nginx ]; then ports="$ports 80/tcp"; else ports="$ports 80/tcp $PANEL_PORT/tcp"; fi
  [ "$SSL" != none ] && ports="$ports $SUB_PORT/tcp" && [ "$MODE" = nginx ] && ports="$ports $PANEL_TLS_PORT/tcp"
  if confirm "ufw активен. Открыть порты $ports?" y; then
    for p in $ports; do ufw allow "$p" >/dev/null; done
    ok "ufw: открыты $ports"
  fi
}

uninstall() {
  step "Удаление L2X Panel"
  if [ "$INTERACTIVE" = 1 ]; then confirm "Удалить панель и Xray? Данные в $DATA_DIR сохранятся" n || exit 0; fi
  systemctl disable --now l2xpanel 2>/dev/null || true
  systemctl disable --now xray 2>/dev/null || true
  rm -f /etc/systemd/system/l2xpanel.service /etc/systemd/system/xray.service /usr/local/bin/l2x
  systemctl daemon-reload
  if [ -f "$NGINX_SITE" ] || [ -d /etc/nginx/l2x ]; then
    rm -rf "$NGINX_SITE" /etc/nginx/sites-enabled/l2xpanel.conf /etc/nginx/l2x /etc/nginx/conf.d/l2x-front.conf
    sed -i '/l2x-panel: public :443 front/d; \#include /etc/nginx/l2x/stream.conf;#d' /etc/nginx/nginx.conf 2>/dev/null || true
    systemctl reload nginx 2>/dev/null || true
  fi
  rm -rf "$APP_DIR"
  ok "Удалено. Данные остались в $DATA_DIR и $ETC_DIR — удалите вручную, если не нужны"
  exit 0
}

current_mode() { grep -q '^HOST=0.0.0.0' "$ENV_FILE" 2>/dev/null && echo direct || echo nginx; }

update() {
  MODE=$(current_mode)
  SSL=none
  fetch_source
  install_packages
  install_xray
  install_code
  install_system
  wait_panel
  ok "Панель обновлена, данные и настройки сохранены"
  printf '\n  Адрес панели: %s%s%s\n  Меню: %sl2x%s\n\n' "$W" "$(/usr/local/bin/l2x url 2>/dev/null)" "$N" "$W" "$N"
  exit 0
}

# ---------------------------------------------------------------- questions
configure() {
  local detected
  detected=$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

  ask PUBLIC_HOST "IP или домен сервера (для ссылок и подписок)" "${L2X_HOST:-$detected}"
  ask ADMIN_USER "Логин администратора" "${L2X_ADMIN:-admin}"
  ask ADMIN_PASSWORD "Пароль администратора" "${L2X_PASSWORD:-$(rand 16)}"
  [ ${#ADMIN_PASSWORD} -ge 8 ] || die "Пароль должен быть не короче 8 символов"
  ask PANEL_PATH "Секретный путь панели (- = без пути)" "${L2X_PATH:-$(rand 12)}"
  PANEL_PATH=${PANEL_PATH#/}; PANEL_PATH=${PANEL_PATH%/}
  [ "$PANEL_PATH" = - ] && PANEL_PATH=""
  [[ -z $PANEL_PATH || $PANEL_PATH =~ ^[A-Za-z0-9_-]+$ ]] || die "Путь: только латиница, цифры, _ и -"

  local m=1
  [ "${L2X_MODE:-nginx}" = direct ] && m=2
  choose m "Как открывать панель?" "$m" \
    "1|Через nginx на порту 80 (рекомендуется)" \
    "2|Напрямую на отдельном порту, без nginx"
  if [ "$m" = 2 ]; then
    MODE=direct
    ask PANEL_PORT "Порт панели" "${L2X_PORT:-2053}"
    [[ $PANEL_PORT =~ ^[0-9]+$ ]] && [ "$PANEL_PORT" -ge 1 ] && [ "$PANEL_PORT" -le 65535 ] || die "Неверный порт"
    case "$PANEL_PORT" in 22|80|443|7443) die "Порт $PANEL_PORT занят SSH/nginx" ;; esac
  else
    MODE=nginx
    PANEL_PORT=80
  fi

  ask XRAY_VERSION "Версия Xray-core (latest или тег, например v26.10.31)" "${XRAY_VERSION:-latest}"
  [ "$XRAY_VERSION" = latest ] && [ -x "$XRAY_BIN" ] && XRAY_VERSION=""

  local s=3 def_domain=""
  case "${L2X_SSL:-none}" in ip) s=1 ;; domain) s=2 ;; esac
  is_ip "$PUBLIC_HOST" || { def_domain=$PUBLIC_HOST; [ "$s" = 1 ] && s=2; }
  choose s "HTTPS для подписок (нужен для Happ и др.) — сертификат Let's Encrypt:" "$s" \
    "1|На IP сервера (без домена, 6 дней, продлевается автоматически)" \
    "2|На домен (90 дней, A-запись домена должна указывать на сервер)" \
    "3|Пропустить (можно позже: Настройки → Сертификаты)"
  SSL=none SSL_DOMAIN="" SSL_EMAIL=""
  if [ "$s" = 1 ]; then
    is_ip "$PUBLIC_HOST" || ask PUBLIC_HOST "Публичный IP сервера" "$detected"
    SSL=ip
  elif [ "$s" = 2 ]; then
    ask SSL_DOMAIN "Домен" "${L2X_DOMAIN:-$def_domain}"
    [ -n "$SSL_DOMAIN" ] || die "Домен не указан"
    SSL=domain
    PUBLIC_HOST=$SSL_DOMAIN
  fi
  [ "$SSL" != none ] && ask SSL_EMAIL "E-mail для Let's Encrypt (необязательно)" "${L2X_EMAIL:-}"

  step "Проверьте параметры"
  printf '  Адрес:          %s\n  Логин:          %s\n  Пароль:         %s\n  Секретный путь: %s\n' \
    "$PUBLIC_HOST" "$ADMIN_USER" "$ADMIN_PASSWORD" "${PANEL_PATH:-нет}"
  printf '  Доступ:         %s\n  Xray-core:      %s\n  HTTPS подписок: %s\n\n' \
    "$([ "$MODE" = nginx ] && echo 'nginx :80' || echo "напрямую :$PANEL_PORT")" \
    "${XRAY_VERSION:-установленный}" "$([ "$SSL" = none ] && echo нет || echo "Let's Encrypt ($SSL)")"
  if [ "$INTERACTIVE" = 1 ]; then confirm "Начать установку?" y || die "Отменено"; fi
}

summary() {
  local base="http://$PUBLIC_HOST" path=${PANEL_PATH:+/$PANEL_PATH}
  [ "$MODE" = direct ] && base="http://$PUBLIC_HOST:$PANEL_PORT"
  printf '\n%s  ════════════════════ L2X Panel установлена ════════════════════%s\n\n' "$G" "$N"
  printf '  Панель:   %s%s%s/%s\n' "$W" "$base" "$path" "$N"
  if [ "$SSL" != none ] && [ "$MODE" = nginx ]; then
    printf '  HTTPS:    %shttps://%s:%s%s/%s\n' "$W" "$PUBLIC_HOST" "$PANEL_TLS_PORT" "$path" "$N"
  fi
  printf '  Логин:    %s%s%s\n  Пароль:   %s%s%s\n' "$W" "$ADMIN_USER" "$N" "$W" "$ADMIN_PASSWORD" "$N"
  if [ "$SSL" != none ]; then
    printf '  Подписки: https://%s:%s/sub/<token>\n' "$PUBLIC_HOST" "$SUB_PORT"
  fi
  printf '\n  Меню управления на сервере: %sl2x%s\n' "$W" "$N"
  printf '  Сохраните пароль — он больше не будет показан (сброс: l2x reset-password).\n\n'
  printf '  Inbounds доступны только через nginx :443 (Xray слушает 127.0.0.1, порты inbounds закрыты iptables).\n'
  printf '  Откройте в файрволе: %s%s.\n\n' \
    "$([ "$MODE" = nginx ] && echo '80/tcp, 443/tcp' || echo "80/tcp, 443/tcp, $PANEL_PORT/tcp")" \
    "$([ "$SSL" != none ] && echo ", $SUB_PORT/tcp$([ "$MODE" = nginx ] && echo ", $PANEL_TLS_PORT/tcp")")"
}

# ---------------------------------------------------------------- main
banner
for a in "$@"; do
  case "$a" in
    --uninstall) uninstall ;;
    --update) [ -f "$ENV_FILE" ] || die "Панель не установлена"; update ;;
  esac
done

if [ -f "$ENV_FILE" ] && [ -f "$APP_DIR/app.py" ]; then
  info "L2X Panel уже установлена"
  if [ "$INTERACTIVE" = 0 ]; then update; fi
  choose act "Что сделать?" 1 \
    "1|Обновить панель (данные и настройки сохраняются)" \
    "2|Удалить панель" \
    "0|Выход"
  case "$act" in
    1) update ;;
    2) uninstall ;;
    *) exit 0 ;;
  esac
fi

configure
fetch_source
install_packages
install_xray
install_code
install_system
write_env
wait_panel
setup_ssl
[ "$SSL" != none ] && wait_panel
open_firewall
summary
