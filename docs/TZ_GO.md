# Техническое задание: L2X Panel (Go)

**Продукт:** веб-панель управления Xray-core с мульти-нодами, custom outbounds и подписками  
**Цель ТЗ:** полная реализация на **Go** (без Python-рантайма панели)  
**Эталон функционала:** текущий L2X Panel ≈ v1.6.4 (`eliot-voodi/l2x-panel`)  
**Лицензия:** MIT  

---

## 1. Цель и границы

### 1.1. Цель

Один бинарник (или минимальный набор бинарников) на Go, который:

- управляет Xray-core (inbounds / clients / routes / balancers / outbounds / DNS / policy);
- отдаёт admin UI + subscription endpoints + REST API;
- поддерживает кластер master↔agent с зеркалированием и failover.

### 1.2. Вне скоупа (v1 Go)

- Переписывание Xray-core / nginx (используются как есть).
- Мобильные нативные клиенты.
- Платежный биллинг (можно заложить хуки API).

### 1.3. Критерий приёмки

Функциональный паритет с Python-панелью 1.6.x по разделам ниже + установка одной командой на Debian/Ubuntu.

---

## 2. Стек (обязательный)

| Слой | Технология |
|------|------------|
| Язык | Go 1.22+ |
| HTTP | `net/http` или **chi** / **echo** / **fiber** (один выбор на проект) |
| UI | server-rendered HTML (`html/template`) или embedded SPA; предпочтительно SSR + HTMX/лёгкий JS (как сейчас) |
| Хранение | JSON store (`/var/lib/l2xpanel/store.json`) на старте; опционально SQLite позже |
| Конфиг Xray | генерация JSON → `xray run -test` → atomic replace → `systemctl restart/reload xray` |
| Front | nginx конфиги (как `front.py`) или Caddy; минимум — совместимость с текущей схемой nginx |
| SSH (nodes) | `golang.org/x/crypto/ssh` |
| Crypto | TOTP, password hashing (argon2id/bcrypt), AES-GCM для секретов |
| Сборка | один static/почти-static binary `l2xpanel`, CLI `l2x` |
| Упаковка | `install.sh`, systemd unit, Docker optional |
| Тесты | `go test`, integration tests с mock xray/nginx |

Запрещено: Python/Node как runtime панели. Допускаются shell-хелперы только в install/update.

---

## 3. Архитектура

```
Клиент VPN ──► nginx:443 / Xray inbounds
                 │
                 ▼
            Xray-core (routing → node_* / warp / custom / direct)
                 │
                 ▼
         WG / custom outbound / node reverse

Admin ──HTTPS──► nginx ──► l2xpanel (:8090)
                              ├─ UI
                              ├─ /agent/* (Bearer)
                              ├─ /panel/api/*
                              └─ /sub/*, /health
```

**Процессы:**

- `l2xpanel.service` — основной демон Go
- `xray.service` — ядро
- `nginx` — TLS front + camouflage

**Фоновые воркеры (goroutines):**

1. Xray watchdog + online/stats poll
2. Outbound health / observatory
3. History / speed samples
4. Panel update check
5. Xray update check
6. Nodes scheduled sync
7. Cert renewal helper
8. Telegram bot long-poll/webhook

---

## 4. Модули Go (пакеты)

Рекомендуемая структура:

```
cmd/l2xpanel/main.go
cmd/l2x/main.go
internal/
  config/          # env, paths, version
  store/           # load/save/mutate, defaults, migrations
  auth/            # session, TOTP, rate-limit login
  xraycfg/         # build_config, apply, test, clean errors
  protocols/       # share links, inbound builders
  outbounds/       # parse URI, WARP, Nord, PIA, WG keys
  front/           # nginx stage/commit/rollback
  nodes/           # provision, push, promote, mirror, schedule
  ops/             # install xray, geo, panel self-update, jobs
  sub/             # subscription formats + headers
  hwid/            # device limits
  api/             # REST
  webhooks/
  tgbot/
  sysmon/
  httpserver/      # UI routes + middleware base_path
web/ui/            # templates + static (embed.FS)
```

---

## 5. Функциональные требования

### 5.1. Auth и безопасность

- Логин/пароль, cookie session, опциональный TOTP.
- Секретный `base_path` панели; публичные только `/health`, `/sub/`, `/panel/api/`, ACME.
- Rate-limit неудачных логинов.
- Шифрование секретов outbound at rest.
- API tokens; agent Bearer token (constant-time compare).

### 5.2. Inbounds

Протоколы: VLESS, VMess, Trojan, Shadowsocks(+2022), Hysteria2, WireGuard, SOCKS, HTTP, dokodemo-door.  
Транспорты: raw, ws, grpc, httpupgrade, xhttp, kcp; TLS/Reality.  
CRUD + enable/disable + привязка outbound.

### 5.3. Clients

- UUID/password, лимиты GB/IP/HWID, expiry, start-on-first-connect, reset cycle.
- Привязка к inbounds и outbound (`direct` / `node_*` / custom / balancers).
- Bulk ops, QR, client page, traffic counters, online list.

### 5.4. Outbounds / Balancers / Routing

- Custom outbounds + URI import.
- WARP one-click, NordLynx, WG keygen.
- Balancers `leastPing` / `leastLoad`; **пустые members → fallback `[direct]`, не эмитить broken observatory**.
- Routes; неизвестные outbound tags на agent → `direct`.

### 5.5. Подписки

Форматы: base64, plain, xray-json, clash-meta, sing-box, HTML.  
Happ headers: profile-title, userinfo, announce, hwid, new-url.  
HTTPS через nginx/LE (domain или IP).

### 5.6. Ops / System

- Install/update Xray с rollback если `-test`/start fail.
- Geo files update.
- Panel self-update: скачать release binary / `install.sh --update`, restart service.
- Backup/restore store (+ TG).
- BBR, speedtest, logs viewer, sysmon dashboard.
- i18n RU/EN, dark/light.

### 5.7. Multi-node (критичный блок, как в 1.6.x)

| Возможность | Требование |
|-------------|------------|
| Provision | SSH domain/login/pass → install agent, token, base_path, optional outbound+mirror |
| Sync | Push clients/inbounds/routes/… на agent |
| Outbound node | Bridge VLESS/WS на агенте → `node_<slug>` на мастере |
| Mirror | Полная копия master data; runtime agent безопасный |
| Schedule sync | Per-node interval: off/5m…24h |
| Update node | Agent API `/agent/update` или SSH |
| Promote | **Сначала** поднять remote master + verify `/health.role`, **потом** demote old; `runtime_preserve` |
| Promote data | Все outbounds кроме outbound на целевую ноду; ссылки → `direct` |
| Restore master | Emergency кнопка/API на агенте |
| Safety | Не держать store lock на время HTTP push; запрет self-provision |

**Agent API:**

- `POST /{base}/agent/apply` — sync payload
- `POST /{base}/agent/update` — `{confirm:yes}` start self-update
- `POST /{base}/agent/promote` — transactional flip to master, rollback on xray fail
- `GET /health` — `{status, version, role, agent}`

---

## 6. Модель данных (store)

Файл JSON (совместимость с текущим желательна для миграции):

```json
{
  "settings": {
    "panel": {"public_host": "", "base_path": "", "title": ""},
    "nodes": {
      "role": "master|agent",
      "agent_enabled": false,
      "agent_token": "",
      "runtime_preserve": false
    },
    "sub": {},
    "security": {},
    "telegram": {},
    "webhooks": {},
    "panel_update": {},
    "xray_update": {}
  },
  "admin": {},
  "inbounds": [],
  "clients": [],
  "outbounds_custom": [],
  "routes": [],
  "balancers": {},
  "dns": {},
  "xray_settings": {},
  "nodes": [
    {
      "id": "uuid",
      "name": "",
      "domain": "",
      "url": "",
      "token": "",
      "base_path": "",
      "enabled": true,
      "sync_clients": true,
      "sync_inbounds": true,
      "as_outbound": false,
      "mirror": false,
      "sync_interval_min": 0,
      "bridge_uuid": "",
      "bridge_path": "",
      "last_sync": "",
      "last_ok": false,
      "last_error": "",
      "panel_version": ""
    }
  ]
}
```

Требование: atomic write (`*.tmp` + rename), `sync.Mutex` / `RWMutex` вокруг mutate.

---

## 7. HTTP поверхность

### 7.1. UI (SSR)

`/login`, `/`, `/inbounds`, `/clients`, `/outbounds`, `/balancers`, `/routing`, `/schema`, `/xray`, `/nodes`, `/logs`, `/settings`, `/bans`, `/api-docs`

### 7.2. Public

`GET /health`, `GET /sub/{token}`, static

### 7.3. Agent

как в §5.8

### 7.4. REST API

Сохранить семантику [API.md](API.md) (токены, CRUD клиентов/inbounds, traffic, online).

---

## 8. Генерация Xray-конфига

Порт логики `panel/xray_runtime.py`:

- inbounds + clients emails;
- outbounds: direct, block, api, custom, node_*;
- balancers + observatory только при валидных members;
- routing: api, user rules, default;
- на agent: `AgentRuntimeStore` — sanitize legacy tags; `runtime_preserve` для локального runtime.

Apply pipeline:

1. stage nginx
2. `xray -test`
3. commit nginx / rollback on fail
4. restart xray

---

## 9. Установка и обновление

`install.sh`:

- зависимости ОС (nginx, xray, curl…);
- скачать `l2xpanel` / `l2x` binary под arch;
- systemd, panel.env, первый admin + base_path;
- опции `--update` (сохранить store/certs).

CLI `l2x`:

- `status`, `restart`, `update`, `backup`, `restore`, `version`.

Self-update панели = замена binary + `systemctl restart l2xpanel`.

---

## 10. Нефункциональные требования

| Параметр | Требование |
|----------|------------|
| Платформа | linux amd64/arm64, Debian 12+ / Ubuntu 22.04+ |
| RAM | ≤150 МБ idle для панели |
| Старт | <2 с cold start binary |
| Надёжность | не блокировать UI store-lock на сетевых sync/promote |
| Совместимость | migrate store из Python 1.6.x без ручного редактирования |
| Наблюдаемость | structured logs (`log/slog`), job log в UI |
| Безопасность | нет plaintext паролей в логах; TLS на front |

---

## 11. Миграция с Python

1. Чтение существующего `store.json` as-is.
2. Те же пути: `/opt/l2xpanel`, `/var/lib/l2xpanel`, `/etc/l2xpanel`.
3. `install.sh --update` заменяет Python unit на Go binary.
4. Feature flag период: dual-run не обязателен, но backup store перед апдейтом — обязателен.
5. Agent API совместим по путям/JSON, чтобы смешанный кластер (Go master + старый agent) работал на время роллаута.

---

## 12. Тест-план (минимум)

- Unit: build_config balancers empty; promote_snapshot remap `node_X→direct`; sync_due intervals.
- Integration: apply xray mock; nginx stage/rollback.
- E2E: provision agent (testcontainers/SSH mock), sync, mirror, schedule tick, promote order (remote first), restore-master.
- Regression: self-host provision rejected; push without holding lock.

---

## 13. Этапы поставки

| Этап | Содержание | Результат |
|------|------------|-----------|
| **M1** | store, auth, UI shell, health, settings | логин + пустой дашборд |
| **M2** | xraycfg + inbounds/clients/routes/outbounds/balancers | полный single-node Xray |
| **M3** | custom outbounds + balancers + schema | мульти-egress |
| **M4** | front/nginx + sub + certs | прод HTTPS/подписки |
| **M5** | ops (xray/panel update, geo, backup), TG, API | ops parity |
| **M6** | nodes (provision/sync/mirror/schedule/promote) | cluster parity 1.6.4 |
| **M7** | install.sh, migrate, docs, release | Go GA |

---

## 14. Критерии Done

- [ ] Один binary обслуживает UI+API+agent+workers
- [ ] Паритет фич с Python 1.6.4 (включая mirror/promote/schedule)
- [ ] Миграция store с живого Python-инстанса
- [ ] `go test ./...` зелёный + e2e checklist пройден
- [ ] Документация: README, API, upgrade guide Python→Go

---

## 15. Связанные документы

- [API.md](API.md) — REST API текущей панели (семантика для порта)
- Эталон кода: `panel/app.py`, `panel/nodes.py`, `panel/xray_runtime.py`, `panel/front.py`, `panel/ops.py`
