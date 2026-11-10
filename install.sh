#!/usr/bin/env bash
# L2X Panel — interactive installer for Debian 12+ / Ubuntu 22.04+
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh)
#
# On an installed server the same command opens a menu: update / reinstall code / uninstall.
#
# Flags:
#   --yes, -y     non-interactive: take answers from the environment or defaults
#   --update [TAG]      dual-slot update (download → start 2nd service → health → nginx flip →
#                       stop old); auto-rollback on health fail; optional Git tag
#   --update-full [TAG] full update (apt + xray + systemd/nginx) + dual-slot cutover
#   --uninstall         remove services and code (data in /var/lib/l2xpanel is kept)
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
#   SKIP_XRAY=1   skip Xray install during --update (panel-only rollback)
#   L2X_REPO, L2X_BRANCH  source repository / branch or tag (default: eliot-voodi/l2x-panel, main)
set -euo pipefail

REPO_URL=${L2X_REPO:-https://github.com/eliot-voodi/l2x-panel}
BRANCH=${L2X_BRANCH:-main}
# Dual-slot layout: only one unit serves traffic; /opt/l2xpanel is a symlink to the active slot.
LIVE_DIR=/opt/l2xpanel-live
NEXT_DIR=/opt/l2xpanel-next
APP_DIR=/opt/l2xpanel
STAGE_DIR=$NEXT_DIR
LIVE_PORT=8090
NEXT_PORT=8091
STAGE_PORT=$NEXT_PORT
PANEL_LIVE_ADDR=127.0.0.1:$LIVE_PORT
PANEL_NEXT_ADDR=127.0.0.1:$NEXT_PORT
DATA_DIR=/var/lib/l2xpanel
ETC_DIR=/etc/l2xpanel
ENV_FILE=$ETC_DIR/panel.env
PANEL_UPSTREAM_CONF=/etc/nginx/conf.d/l2x-panel-upstream.conf
PANEL_UPSTREAM_STATE=$ETC_DIR/panel_upstream
PANEL_SLOT_FILE=$ETC_DIR/panel_slot
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
fetch_retry() {
  # fetch_retry <url> <dest-file>: retries GitHub 5xx / network errors; empty dest = failure
  local url=$1 dest=$2 attempt code
  for attempt in 1 2 3 4 5; do
    code=$(curl -sS -L --connect-timeout 20 --max-time 300 \
      -o "$dest" -w '%{http_code}' -H 'User-Agent: L2XPanel-Installer/1.0' "$url" || true)
    if [ "$code" = "200" ] && [ -s "$dest" ]; then
      return 0
    fi
    warn "$url → HTTP ${code:-?}, повтор через $((attempt * 3))с ($attempt/5)" >&2
    rm -f "$dest"
    sleep $((attempt * 3))
  done
  return 1
}

xray_latest_tag() {
  # GitHub API first; on 5xx fall back to the releases/latest redirect (no API quota/outage)
  local tmp tag=""
  tmp=$(mktemp)
  if fetch_retry https://api.github.com/repos/XTLS/Xray-core/releases/latest "$tmp"; then
    tag=$(jq -r '.tag_name // empty' "$tmp" 2>/dev/null || true)
  fi
  rm -f "$tmp"
  if [ -z "$tag" ]; then
    tag=$(curl -sS -o /dev/null -w '%{redirect_url}' --connect-timeout 20 --max-time 60 \
      https://github.com/XTLS/Xray-core/releases/latest 2>/dev/null | sed -E 's|.*/tag/||' || true)
  fi
  printf '%s' "$tag"
}

_download_repo_tarball() {
  # GitHub archive endpoints flake with 503; try several URLs with retries.
  # Never pipe curl|tar — a failed HTML/error body corrupts the extract.
  # BRANCH may be a branch (main) or a release tag (v1.9.72).
  # Prefer heads for branch-like refs and tags for version-like refs — otherwise a
  # fresh install with L2X_BRANCH=main wastes ~45s retrying the non-existent tags/main.
  local dest=$1 owner repo
  owner=$(printf '%s' "$REPO_URL" | sed -E 's|https?://github.com/||;s|/+$||' | cut -d/ -f1)
  repo=$(printf '%s' "$REPO_URL" | sed -E 's|https?://github.com/||;s|/+$||' | cut -d/ -f2)
  [ -n "$owner" ] && [ -n "$repo" ] || die "Некорректный L2X_REPO: $REPO_URL"
  local tag_urls=(
    "https://codeload.github.com/${owner}/${repo}/tar.gz/refs/tags/${BRANCH}"
    "https://github.com/${owner}/${repo}/archive/refs/tags/${BRANCH}.tar.gz"
  )
  local head_urls=(
    "https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${BRANCH}"
    "https://github.com/${owner}/${repo}/archive/refs/heads/${BRANCH}.tar.gz"
  )
  local fallback_urls=(
    "https://github.com/${owner}/${repo}/archive/${BRANCH}.tar.gz"
    "https://codeload.github.com/${owner}/${repo}/tar.gz/${BRANCH}"
  )
  local urls=()
  if [[ "$BRANCH" =~ ^[vV]?[0-9]+\.[0-9]+ ]]; then
    urls=("${tag_urls[@]}" "${head_urls[@]}" "${fallback_urls[@]}")
  else
    urls=("${head_urls[@]}" "${tag_urls[@]}" "${fallback_urls[@]}")
  fi
  local url attempt code
  for url in "${urls[@]}"; do
    for attempt in 1 2 3 4 5; do
      info "Загрузка $url (попытка $attempt/5)"
      code=$(curl -sS -L --connect-timeout 20 --max-time 180 \
        -o "$dest" -w '%{http_code}' \
        -H 'User-Agent: L2XPanel-Installer/1.0' \
        "$url" || true)
      if [ "$code" = "200" ] && [ -s "$dest" ] && gzip -t "$dest" 2>/dev/null; then
        ok "архив скачан ($(wc -c <"$dest") байт)"
        return 0
      fi
      # 404 = wrong ref type (tag vs branch) — skip retries, try next URL immediately
      if [ "$code" = "404" ]; then
        warn "HTTP 404 — нет такого ref, следующий URL"
        rm -f "$dest"
        break
      fi
      warn "HTTP ${code:-?} / битый архив — повтор через $((attempt * 3))с"
      rm -f "$dest"
      sleep $((attempt * 3))
    done
  done
  return 1
}

fetch_source() {
  SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)
  if [ -f "$SCRIPT_DIR/panel/app.py" ]; then
    SRC=$SCRIPT_DIR
    return
  fi
  command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null; }
  SRC=$(mktemp -d)
  # Global (not local): the EXIT trap runs after this function returns, under set -u
  SRC_TARBALL=$(mktemp)
  trap 'rm -rf "${SRC:-}" "${SRC_TARBALL:-}"' EXIT
  info "Загрузка $REPO_URL ($BRANCH)"
  _download_repo_tarball "$SRC_TARBALL" || die "Не удалось скачать исходники с GitHub (503/сеть). Повторите позже или задайте L2X_REPO на зеркало."
  tar -xz -C "$SRC" --strip-components=1 -f "$SRC_TARBALL"
  rm -f "$SRC_TARBALL"
  [ -f "$SRC/panel/app.py" ] || die "В архиве нет panel/app.py"
}

install_packages() {
  step "Пакеты"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    curl ca-certificates unzip jq openssl socat cron kmod iproute2 iptables \
    python3 python3-venv \
    ppp xl2tpd strongswan strongswan-starter strongswan-charon libstrongswan-standard-plugins wireguard-tools >/dev/null
  # Debian 13+: metapackage may pull charon-systemd (conflicts with strongswan-starter/ipsec.conf path)
  if dpkg -l charon-systemd 2>/dev/null | grep -q '^ii'; then
    apt-get install -y -qq --no-install-recommends strongswan-charon >/dev/null || true
  fi
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
  if [ "${SKIP_XRAY:-}" = "1" ]; then
    if [ -x "$XRAY_BIN" ]; then
      ok "Пропуск Xray (SKIP_XRAY=1): $("$XRAY_BIN" version 2>/dev/null | head -1 || echo installed)"
    else
      warn "SKIP_XRAY=1, но бинарник Xray не найден — пропускаю"
    fi
    return
  fi
  if [ -x "$XRAY_BIN" ] && [ -z "${XRAY_VERSION:-}" ]; then
    ok "Уже установлен: $("$XRAY_BIN" version | head -1 | awk '{print $2}')"
  else
    local ver=${XRAY_VERSION:-latest} tmp
    if [ "$ver" = latest ]; then
      ver=$(xray_latest_tag)
      [ -n "$ver" ] || die "Не удалось определить последнюю версию Xray-core (GitHub недоступен). Повторите позже или задайте XRAY_VERSION."
    fi
    info "Загрузка Xray-core $ver"
    tmp=$(mktemp -d)
    fetch_retry "https://github.com/XTLS/Xray-core/releases/download/$ver/$XRAY_ASSET" "$tmp/xray.zip" \
      || die "Не удалось скачать Xray-core $ver с GitHub. Повторите позже."
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

_req_hash() {
  # Stable hash of requirements.txt for conditional pip
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  else
    cksum "$1" 2>/dev/null | awk '{print $1}'
  fi
}

# ---- dual-slot helpers (live :8090 / next :8091; nginx flips once; old unit stops after health)
active_slot() { tr -d '[:space:]' <"$PANEL_SLOT_FILE" 2>/dev/null || echo live; }
slot_dir()  { [ "${1:-}" = next ] && echo "$NEXT_DIR" || echo "$LIVE_DIR"; }
slot_port() { [ "${1:-}" = next ] && echo "$NEXT_PORT" || echo "$LIVE_PORT"; }
slot_unit() { [ "${1:-}" = next ] && echo l2xpanel-next || echo l2xpanel; }
slot_addr() { echo "127.0.0.1:$(slot_port "${1:-live}")"; }
active_dir()  { slot_dir "$(active_slot)"; }
active_port() { slot_port "$(active_slot)"; }
active_unit() { slot_unit "$(active_slot)"; }
active_addr() { slot_addr "$(active_slot)"; }
inactive_slot() { [ "$(active_slot)" = next ] && echo live || echo next; }
inactive_dir()  { slot_dir "$(inactive_slot)"; }
inactive_port() { slot_port "$(inactive_slot)"; }
inactive_unit() { slot_unit "$(inactive_slot)"; }
inactive_addr() { slot_addr "$(inactive_slot)"; }

link_app_dir() {
  # /opt/l2xpanel → active slot (CLI, py(), VERSION readers).
  # Safe to call only when nothing must keep serving from a classic real /opt/l2xpanel.
  local target=${1:-$(active_dir)}
  mkdir -p "$target"
  if [ -L "$APP_DIR" ]; then
    ln -sfn "$target" "$APP_DIR"
    return 0
  fi
  if [ -e "$APP_DIR" ]; then
    # Retire classic real directory in favour of the symlink (panel unit already stopped).
    rm -rf "$APP_DIR"
  fi
  ln -sfn "$target" "$APP_DIR"
}

write_panel_slot() {
  local slot=${1:-live}
  mkdir -p "$ETC_DIR"
  printf '%s\n' "$slot" >"$PANEL_SLOT_FILE"
  link_app_dir "$(slot_dir "$slot")"
}

ensure_slot_layout() {
  # Migrate classic /opt/l2xpanel (real dir) + optional .stage into live/next slots.
  # Never mv/rm the running tree here — only copy; symlink is created at cutover (write_panel_slot).
  mkdir -p "$ETC_DIR" "$LIVE_DIR" "$NEXT_DIR"
  if [ -L "$APP_DIR" ]; then
    [ -f "$PANEL_SLOT_FILE" ] || printf 'live\n' >"$PANEL_SLOT_FILE"
    return 0
  fi
  if [ -d "$APP_DIR" ]; then
    if [ ! -f "$LIVE_DIR/app.py" ]; then
      info "Миграция в dual-slot: копирование $APP_DIR → $LIVE_DIR (процесс не трогаем)"
      cp -a "$APP_DIR"/. "$LIVE_DIR"/
    fi
    [ -f "$PANEL_SLOT_FILE" ] || printf 'live\n' >"$PANEL_SLOT_FILE"
  else
    write_panel_slot live
  fi
  # Old blue-green stage path → next slot
  if [ -d /opt/l2xpanel.stage ] && [ ! -f "$NEXT_DIR/app.py" ]; then
    cp -a /opt/l2xpanel.stage/. "$NEXT_DIR"/ 2>/dev/null || true
  fi
  rm -rf /opt/l2xpanel.stage 2>/dev/null || true
  if [ ! -f "$PANEL_UPSTREAM_STATE" ]; then
    write_panel_upstream "$PANEL_LIVE_ADDR"
  fi
}

enable_active_unit() {
  local on off
  on=$(active_unit)
  off=$(inactive_unit)
  systemctl disable "$off" 2>/dev/null || true
  systemctl enable "$on" 2>/dev/null || true
}

snapshot_panel() {
  # Extra copy of the active slot (dual-slot already keeps the other tree for rollback).
  local prev=/opt/l2xpanel.prev src
  ensure_slot_layout
  src=$(active_dir)
  rm -rf "$prev"
  mkdir -p "$prev"
  if [ -d "$src" ]; then
    shopt -s dotglob nullglob
    for item in "$src"/*; do
      base=$(basename "$item")
      case "$base" in
        .venv|__pycache__|*.pyc) continue ;;
      esac
      cp -a "$item" "$prev/"
    done
    shopt -u dotglob nullglob
    printf '%s\n' "$(tr -d '[:space:]' <"$src/VERSION" 2>/dev/null || echo unknown)" >"$prev/.snapshot_version"
    ok "Снимок активного слота → $prev (v$(cat "$prev/.snapshot_version" 2>/dev/null || echo '?'))"
  fi
}

restore_panel_snapshot() {
  # Emergency: restore into the currently active slot dir from /opt/l2xpanel.prev
  local prev=/opt/l2xpanel.prev dest
  ensure_slot_layout
  dest=$(active_dir)
  [ -d "$prev" ] || { warn "Нет снимка $prev — откат невозможен"; return 1; }
  step "Откат панели на предыдущую рабочую версию ($dest)"
  find "$dest" -maxdepth 1 -mindepth 1 ! -name '.venv' -exec rm -rf {} +
  shopt -s dotglob nullglob
  for item in "$prev"/*; do
    base=$(basename "$item")
    [ "$base" = ".snapshot_version" ] && continue
    cp -a "$item" "$dest/"
  done
  shopt -u dotglob nullglob
  link_app_dir "$dest"
  local ver
  ver=$(tr -d '[:space:]' <"$dest/VERSION" 2>/dev/null || echo '?')
  ok "Восстановлено v$ver из $prev"
  return 0
}

install_code_into() {
  # Install panel code into $1 (a concrete slot dir — never the symlink alone).
  local dest=$1
  local venv_src=""
  [ -n "$dest" ] || die "install_code_into: пустой путь"
  mkdir -p "$dest" "$DATA_DIR" "$ETC_DIR/certs"
  chmod 700 "$DATA_DIR" "$ETC_DIR"
  rm -rf "$dest/ui"
  # shellcheck disable=SC2086
  rm -f "$dest"/*.py
  cp -a "$SRC/panel/." "$dest/"
  # Prefer repo-root VERSION (release source of truth) over a stale panel/VERSION copy.
  if [ -f "$SRC/VERSION" ]; then
    install -m 644 "$SRC/VERSION" "$dest/VERSION"
  fi
  find "$dest" -name '__pycache__' -prune -exec rm -rf {} +
  # Prefer cloning venv from the other (running) slot to skip cold pip when possible.
  if [ -x "$(active_dir)/.venv/bin/uvicorn" ]; then
    venv_src=$(active_dir)
  elif [ -x "$LIVE_DIR/.venv/bin/uvicorn" ]; then
    venv_src=$LIVE_DIR
  elif [ -x "$NEXT_DIR/.venv/bin/uvicorn" ]; then
    venv_src=$NEXT_DIR
  fi
  if [ ! -x "$dest/.venv/bin/uvicorn" ]; then
    if [ -n "$venv_src" ] && [ "$venv_src" != "$dest" ] && [ -x "$venv_src/.venv/bin/uvicorn" ]; then
      info "Клон .venv с $venv_src → $dest"
      rm -rf "$dest/.venv"
      cp -a "$venv_src/.venv" "$dest/.venv"
    else
      python3 -m venv "$dest/.venv"
      "$dest/.venv/bin/pip" install -q --upgrade pip
    fi
  fi
  local req=$dest/requirements.txt
  local hash_file=$dest/.venv/.req_hash
  local new_hash old_hash=""
  new_hash=$(_req_hash "$req")
  [ -f "$hash_file" ] && old_hash=$(cat "$hash_file" 2>/dev/null || true)
  if [ ! -x "$dest/.venv/bin/uvicorn" ] || [ "$new_hash" != "$old_hash" ]; then
    info "pip install → $dest (requirements изменились или venv пуст)"
    "$dest/.venv/bin/pip" install -q -r "$req"
    printf '%s\n' "$new_hash" >"$hash_file"
  else
    ok "pip пропущен — requirements без изменений ($dest)"
  fi
  local ver
  ver=$(tr -d '[:space:]' <"$dest/VERSION" 2>/dev/null || echo '?')
  ok "Код в $dest (v$ver)"
}

install_code() {
  step "Панель"
  ensure_slot_layout
  install_code_into "$LIVE_DIR"
  write_panel_slot live
  install -m 755 "$SRC/scripts/l2x.sh" /usr/local/bin/l2x
  ok "Данные в $DATA_DIR"
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
  # -e: skip unknown keys (e.g. nf_conntrack when module not loaded yet)
  sysctl -e -p /etc/sysctl.d/99-l2xpanel.conf >/dev/null || true
  install -m 644 "$SRC/deploy/modules.conf" /etc/modules-load.d/l2xpanel.conf
  printf 'tcp_bbr\n' > /etc/modules-load.d/l2x-perf.conf
  while read -r mod; do modprobe "$mod" 2>/dev/null || true; done < "$SRC/deploy/modules.conf"
  modprobe tcp_bbr 2>/dev/null || true

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
  install -m 644 "$SRC/deploy/l2xpanel-next.service" /etc/systemd/system/l2xpanel-next.service
  systemctl daemon-reload
  systemctl enable -q strongswan-starter xl2tpd xray 2>/dev/null || true
  ensure_slot_layout
  enable_active_unit
  systemctl restart strongswan-starter xl2tpd 2>/dev/null || warn "strongSwan/xl2tpd не запустились — L2TP-туннели будут недоступны"

  mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge" /etc/nginx/l2x
  if [ "$MODE" = nginx ]; then
    install -m 644 "$SRC/deploy/nginx.conf" "$NGINX_SITE"
    write_panel_upstream "$(active_addr)"
  else
    install -m 644 "$SRC/deploy/nginx-acme.conf" "$NGINX_SITE"
  fi
  ln -sfn "$NGINX_SITE" /etc/nginx/sites-enabled/l2xpanel.conf
  rm -f /etc/nginx/sites-enabled/default
  # WS flood → EMFILE without raised FD limits (default worker_connections ~768)
  mkdir -p /etc/systemd/system/nginx.service.d
  install -m 644 "$SRC/deploy/nginx-nofile.conf" /etc/systemd/system/nginx.service.d/l2x-nofile.conf
  if [ -f /etc/nginx/nginx.conf ]; then
    sed -i 's/worker_connections [0-9]*;/worker_connections 16384;/' /etc/nginx/nginx.conf
    grep -qE '^[[:space:]]*worker_rlimit_nofile[[:space:]]' /etc/nginx/nginx.conf \
      || sed -i '/^[[:space:]]*worker_processes/a worker_rlimit_nofile 1048576;' /etc/nginx/nginx.conf
    sed -i 's/worker_rlimit_nofile [0-9]*;/worker_rlimit_nofile 1048576;/' /etc/nginx/nginx.conf
  fi
  systemctl daemon-reload
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
  rm -f "$DATA_DIR/admin.json" "$DATA_DIR/admins.json"
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

wait_panel_health_port() {
  # Return 0 if /health answers on $1; do not die (caller may rollback).
  local port=${1:-8090} secs=${2:-40} i
  for i in $(seq 1 "$secs"); do
    if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_panel_health() {
  local secs=${1:-40} port
  ensure_slot_layout
  port=$(active_port)
  if wait_panel_health_port "${port:-8090}" "$secs"; then
    scrub_env_password
    return 0
  fi
  return 1
}

wait_panel() {
  ensure_slot_layout
  systemctl restart xray "$(active_unit)"
  if wait_panel_health 40; then
    return 0
  fi
  die "Панель не запустилась: journalctl -u $(active_unit) -n 50"
}

write_panel_upstream() {
  # Named nginx upstream used by front configs (dual-slot cutover flips only this file).
  local addr=${1:-$PANEL_LIVE_ADDR}
  mkdir -p "$(dirname "$PANEL_UPSTREAM_CONF")" "$ETC_DIR"
  cat >"$PANEL_UPSTREAM_CONF" <<EOF
# managed by l2x-panel — generated, edits are overwritten
upstream l2x_panel_backend {
    server ${addr};
    keepalive 32;
}
EOF
  printf '%s\n' "$addr" >"$PANEL_UPSTREAM_STATE"
}

migrate_nginx_to_named_upstream() {
  # Old panels proxied to 127.0.0.1:8090 directly — rewrite to named upstream once.
  local f
  write_panel_upstream "$(active_addr)"
  for f in /etc/nginx/l2x/*.conf /etc/nginx/conf.d/l2x-front.conf; do
    [ -f "$f" ] || continue
    sed -i 's|proxy_pass http://127\.0\.0\.1:8090;|proxy_pass http://l2x_panel_backend;|g' "$f"
    sed -i 's|proxy_pass http://127\.0\.0\.1:8091;|proxy_pass http://l2x_panel_backend;|g' "$f"
  done
}

flip_panel_upstream() {
  local addr=$1
  write_panel_upstream "$addr"
  nginx -t -q 2>/dev/null || return 1
  systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || return 1
  return 0
}

cleanup_inactive() {
  # Abort path: new slot failed health — stop it, leave active untouched.
  local unit
  unit=$(inactive_unit)
  systemctl stop "$unit" 2>/dev/null || true
  systemctl disable "$unit" 2>/dev/null || true
}

prepare_inactive_slot() {
  ensure_slot_layout
  local dest
  dest=$(inactive_dir)
  step "Скачивание обновления в слот $(inactive_slot) ($dest)"
  install_code_into "$dest"
  install -m 755 "$SRC/scripts/l2x.sh" /usr/local/bin/l2x
  install -m 644 "$SRC/deploy/l2xpanel.service" /etc/systemd/system/l2xpanel.service
  install -m 644 "$SRC/deploy/l2xpanel-next.service" /etc/systemd/system/l2xpanel-next.service
  systemctl daemon-reload
}

# Back-compat alias used by older call sites / docs
prepare_stage_units() { prepare_inactive_slot; }
cleanup_stage() { cleanup_inactive; }

cutover_blue_green() {
  # Dual-slot zero-downtime cutover (nginx mode):
  #   1) new code already in inactive slot
  #   2) start inactive unit → /health
  #   3) nginx flip to new port (ONE flip — no promote / flip-back)
  #   4) stop old unit; keep its tree for the next rollback/update
  local before after new_slot old_slot new_unit old_unit new_port old_port new_dir old_dir new_addr
  ensure_slot_layout
  old_slot=$(active_slot)
  new_slot=$(inactive_slot)
  old_unit=$(slot_unit "$old_slot")
  new_unit=$(slot_unit "$new_slot")
  old_port=$(slot_port "$old_slot")
  new_port=$(slot_port "$new_slot")
  old_dir=$(slot_dir "$old_slot")
  new_dir=$(slot_dir "$new_slot")
  new_addr=$(slot_addr "$new_slot")
  before=$(tr -d '[:space:]' <"$old_dir/VERSION" 2>/dev/null || echo '?')

  migrate_nginx_to_named_upstream
  # Keep traffic on the CURRENT active addr (do not force :8090 — may already be on next).
  write_panel_upstream "$(active_addr)"
  nginx -t -q 2>/dev/null || { cleanup_inactive; die "nginx -t после миграции upstream"; }
  systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true

  step "Старт новой панели $new_unit :$new_port (старая $old_unit не трогаем)"
  systemctl stop "$new_unit" 2>/dev/null || true
  systemctl start "$new_unit"
  if ! wait_panel_health_port "$new_port" 45; then
    warn "Новая v$(tr -d '[:space:]' <"$new_dir/VERSION" 2>/dev/null || echo '?') не ответила на /health — активная панель работает"
    cleanup_inactive
    die "Обновление отменено: journalctl -u $new_unit -n 50"
  fi
  ok "Новая панель здорова на :$new_port"

  step "Nginx → :$new_port (единственный flip)"
  if ! flip_panel_upstream "$new_addr"; then
    warn "Не удалось переключить upstream — трафик остаётся на :$old_port"
    cleanup_inactive
    flip_panel_upstream "$(slot_addr "$old_slot")" || true
    die "nginx reload на новый слот не удался"
  fi

  step "Остановка старой службы $old_unit (клиенты уже на новой)"
  systemctl stop "$old_unit" 2>/dev/null || true
  write_panel_slot "$new_slot"
  enable_active_unit

  # Prove the new slot still answers after ownership flip (same process — should be instant).
  if ! wait_panel_health_port "$new_port" 15; then
    warn "Новый слот потерял /health после cutover — откат на старый слот"
    systemctl start "$old_unit" 2>/dev/null || true
    if wait_panel_health_port "$old_port" 40; then
      flip_panel_upstream "$(slot_addr "$old_slot")" || true
      write_panel_slot "$old_slot"
      enable_active_unit
      cleanup_inactive
      die "Обновление не удалось, восстановлена рабочая v$before"
    fi
    die "Критично: оба слота не отвечают — journalctl -u $new_unit -u $old_unit -n 80"
  fi

  scrub_env_password
  after=$(tr -d '[:space:]' <"$new_dir/VERSION" 2>/dev/null || echo '?')
  ok "Панель: v$before → $after (dual-slot $old_slot→$new_slot, без простоя)"
  printf '\n  Адрес панели: %s%s%s\n  Активный слот: %s%s%s (:%s)\n  Меню: %sl2x%s\n\n' \
    "$W" "$(/usr/local/bin/l2x url 2>/dev/null)" "$N" \
    "$W" "$new_slot" "$N" "$new_port" \
    "$W" "$N"
}

py() {
  ensure_slot_layout
  local home
  home=$(active_dir)
  (cd "$home" && set -a && . "$ENV_FILE" && set +a && HOME=/root "$home/.venv/bin/python" - "$@")
}

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
  systemctl stop "$(active_unit)" 2>/dev/null || systemctl stop l2xpanel 2>/dev/null || true
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
  systemctl disable --now l2xpanel l2xpanel-next 2>/dev/null || true
  systemctl disable --now xray 2>/dev/null || true
  rm -f /etc/systemd/system/l2xpanel.service /etc/systemd/system/l2xpanel-next.service \
        /etc/systemd/system/xray.service /usr/local/bin/l2x
  systemctl daemon-reload
  if [ -f "$NGINX_SITE" ] || [ -d /etc/nginx/l2x ]; then
    rm -rf "$NGINX_SITE" /etc/nginx/sites-enabled/l2xpanel.conf /etc/nginx/l2x \
           /etc/nginx/conf.d/l2x-front.conf "$PANEL_UPSTREAM_CONF"
    sed -i '/l2x-panel: public :443 front/d; \#include /etc/nginx/l2x/stream.conf;#d' /etc/nginx/nginx.conf 2>/dev/null || true
    systemctl reload nginx 2>/dev/null || true
  fi
  rm -rf "$APP_DIR" "$LIVE_DIR" "$NEXT_DIR" /opt/l2xpanel.stage /opt/l2xpanel.prev
  ok "Удалено. Данные остались в $DATA_DIR и $ETC_DIR — удалите вручную, если не нужны"
  exit 0
}

current_mode() { grep -q '^HOST=0.0.0.0' "$ENV_FILE" 2>/dev/null && echo direct || echo nginx; }

update_inplace_direct() {
  # Direct mode shares one public port — validate on next:8091, then brief restart of live.
  local before after
  ensure_slot_layout
  write_panel_slot live
  before=$(tr -d '[:space:]' <"$LIVE_DIR/VERSION" 2>/dev/null || echo '?')
  step "Скачивание обновления в $NEXT_DIR"
  install_code_into "$NEXT_DIR"
  install -m 755 "$SRC/scripts/l2x.sh" /usr/local/bin/l2x
  install -m 644 "$SRC/deploy/l2xpanel.service" /etc/systemd/system/l2xpanel.service
  install -m 644 "$SRC/deploy/l2xpanel-next.service" /etc/systemd/system/l2xpanel-next.service
  systemctl daemon-reload
  step "Проверка новой версии на :$NEXT_PORT (direct)"
  systemctl stop l2xpanel-next 2>/dev/null || true
  systemctl start l2xpanel-next
  if ! wait_panel_health_port "$NEXT_PORT" 45; then
    warn "Новая версия не прошла /health на next — live не трогаем"
    cleanup_inactive
    die "Обновление отменено: journalctl -u l2xpanel-next -n 50"
  fi
  systemctl stop l2xpanel-next 2>/dev/null || true
  step "Установка проверенного кода в live + рестарт (краткий простой)"
  systemctl stop l2xpanel 2>/dev/null || true
  install_code_into "$LIVE_DIR"
  link_app_dir "$LIVE_DIR"
  enable_active_unit
  systemctl start l2xpanel
  if ! wait_panel_health 40; then
    warn "v$(tr -d '[:space:]' <"$LIVE_DIR/VERSION" 2>/dev/null || echo '?') не ответила — откат на v$before"
    restore_panel_snapshot || true
    systemctl restart l2xpanel
    if wait_panel_health 40; then
      die "Обновление не удалось, восстановлена рабочая v$(tr -d '[:space:]' <"$LIVE_DIR/VERSION" 2>/dev/null || echo "$before")"
    fi
    die "Обновление и откат не подняли панель: journalctl -u l2xpanel -n 80"
  fi
  after=$(tr -d '[:space:]' <"$LIVE_DIR/VERSION" 2>/dev/null || echo '?')
  ok "Панель: v$before → $after (direct, минимальный простой)"
  printf '\n  Адрес панели: %s%s%s\n  Меню: %sl2x%s\n\n' "$W" "$(/usr/local/bin/l2x url 2>/dev/null)" "$N" "$W" "$N"
}

update_full() {
  # Slow path: apt + xray + systemd/nginx — for major upgrades / broken hosts.
  MODE=$(current_mode)
  SSL=none
  info "Полное обновление: $REPO_URL @ $BRANCH${SKIP_XRAY:+ (Xray не трогаем)}"
  ensure_slot_layout
  snapshot_panel
  fetch_source
  install_packages
  install_xray
  install_system
  systemctl restart xray 2>/dev/null || true
  if [ "$MODE" = nginx ]; then
    info "Dual-slot cutover (nginx) — панель не должна падать"
    prepare_inactive_slot
    cutover_blue_green
  else
    update_inplace_direct
  fi
  exit 0
}

update() {
  # Fast path: download to inactive slot → start 2nd service → health → nginx flip → stop old.
  MODE=$(current_mode)
  SSL=none
  SKIP_XRAY=${SKIP_XRAY:-1}
  export SKIP_XRAY
  if [ "$MODE" = nginx ]; then
    info "Dual-slot обновление: $REPO_URL @ $BRANCH (без простоя панели)"
  else
    info "Обновление (direct): $REPO_URL @ $BRANCH — сначала проверка на next :$NEXT_PORT"
  fi
  ensure_slot_layout
  snapshot_panel
  fetch_source
  if [ "$MODE" = nginx ]; then
    prepare_inactive_slot
    cutover_blue_green
  else
    update_inplace_direct
  fi
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
  ask PANEL_PATH "Секретный путь панели" "${L2X_PATH:-$(rand 12)}"
  PANEL_PATH=${PANEL_PATH#/}; PANEL_PATH=${PANEL_PATH%/}
  [ -n "$PANEL_PATH" ] || PANEL_PATH=$(rand 12)
  [[ $PANEL_PATH =~ ^[A-Za-z0-9_-]+$ ]] || die "Путь: только латиница, цифры, _ и -"

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
  local base="https://$PUBLIC_HOST" path=/$PANEL_PATH
  is_ip "$PUBLIC_HOST" && base="http://$PUBLIC_HOST"
  local ver
  ver=$(tr -d '[:space:]' <"$APP_DIR/VERSION" 2>/dev/null || echo '?')
  printf '\n%s  ════════════════════ L2X Panel %s установлена ════════════════════%s\n\n' "$G" "$ver" "$N"
  printf '  Панель:   %s%s%s/%s   (корень сайта и прочие пути уводят на ya.ru)\n' "$W" "$base" "$path" "$N"
  printf '  Логин:    %s%s%s\n  Пароль:   %s%s%s\n' "$W" "$ADMIN_USER" "$N" "$W" "$ADMIN_PASSWORD" "$N"
  printf '  Подписки: %s/sub/<token>\n' "$base"
  printf '\n  Меню управления на сервере: %sl2x%s\n' "$W" "$N"
  printf '  Сохраните пароль — он больше не будет показан (сброс: l2x reset-password).\n\n'
  printf '  Inbounds доступны только через nginx :443 (Xray слушает 127.0.0.1, порты inbounds закрыты iptables).\n'
  printf '  Откройте в файрволе: 80/tcp, 443/tcp.\n\n'
}

# ---------------------------------------------------------------- main
detach_from_panel_cgroup() {
  # Cutover stops the old panel unit; systemd kills its whole cgroup. When the update was
  # started by the panel itself (master → agent), re-run in a transient unit that survives it.
  [ "${L2X_DETACHED:-0}" = 1 ] && return 0
  grep -qE 'l2xpanel(-next)?\.service' /proc/self/cgroup 2>/dev/null || return 0
  command -v systemd-run >/dev/null 2>&1 || return 0
  local tmp=/root/.l2x-install.sh log=/var/log/l2xpanel-update-sh.log rc a args=""
  for a in "$@"; do
    case "$a" in *[!A-Za-z0-9._-]*) return 0 ;; esac
    args="$args $a"
  done
  curl -fsSL "${L2X_INSTALL_URL:-https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh}" -o "$tmp" \
    || { warn "Не удалось скачать install.sh для detach — продолжаю в cgroup панели"; return 0; }
  info "Обновление запущено из панели — выполняю вне её cgroup (systemd-run)"
  set +e
  systemd-run --unit=l2xpanel-update-sh --collect --quiet --wait -p KillMode=process \
    --setenv=L2X_DETACHED=1 --setenv=L2X_BRANCH="$BRANCH" \
    --setenv=SKIP_XRAY="${SKIP_XRAY:-}" --setenv=XRAY_VERSION="${XRAY_VERSION:-}" \
    --setenv=L2X_REPO="$REPO_URL" \
    /bin/bash -c "bash '$tmp'$args </dev/null >'$log' 2>&1"
  rc=$?
  set -e
  cat "$log" 2>/dev/null || true
  exit "$rc"
}

banner
case " $* " in
  *" --update "*|*" --update-full "*) detach_from_panel_cgroup "$@" ;;
esac
# Parse --update/--update-full [TAG] / --uninstall; TAG may be v1.9.72 (sets L2X_BRANCH).
_args=("$@")
_i=0
_take_tag() {
  next="${_args[$((_i + 1))]:-}"
  if [ -n "$next" ] && [[ "$next" != -* ]]; then
    BRANCH=$next
    export L2X_BRANCH=$BRANCH
    [ -n "${XRAY_VERSION:-}" ] || SKIP_XRAY=${SKIP_XRAY:-1}
    export SKIP_XRAY
    _i=$((_i + 1))
  fi
}
while [ "$_i" -lt "${#_args[@]}" ]; do
  a="${_args[$_i]}"
  case "$a" in
    --uninstall) uninstall ;;
    --update-full)
      [ -f "$ENV_FILE" ] || die "Панель не установлена"
      _take_tag
      update_full
      ;;
    --update)
      [ -f "$ENV_FILE" ] || die "Панель не установлена"
      _take_tag
      update
      ;;
  esac
  _i=$((_i + 1))
done

# Heal classic → dual-slot layout before the manage menu (APP_DIR becomes a symlink).
[ -f "$ENV_FILE" ] && ensure_slot_layout 2>/dev/null || true
if [ -f "$ENV_FILE" ] && { [ -f "$APP_DIR/app.py" ] || [ -f "$LIVE_DIR/app.py" ]; }; then
  info "L2X Panel уже установлена"
  if [ "$INTERACTIVE" = 0 ]; then update; fi
  choose act "Что сделать?" 1 \
    "1|Обновить панель (dual-slot, без простоя)" \
    "2|Полное обновление (apt + xray + nginx)" \
    "3|Удалить панель" \
    "0|Выход"
  case "$act" in
    1) update ;;
    2) update_full ;;
    3) uninstall ;;
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
