# ТЗ: L2X Tunnel Agent (Go)

**Продукт:** высокоскоростной L4 UDP-туннель для NAT-нод L2X Panel  
**Статус:** утверждено  
**Связанные документы:** [TZ_GO.md](TZ_GO.md) (полная панель на Go — вне скоупа этого ТЗ), [API.md](API.md)  
**Цель:** заменить медленный Xray reverse (VLESS+XHTTP+Mux) на свой datapath мастер↔агент с приоритетом direct (hole punch) и жёсткими лимитами CPU/RAM на ноде **1 vCPU / 1 ГБ RAM / 40 ГБ**.

---

## 1. Цель и границы

### 1.1. Цель

Агент на Go на машине **без белого IP** держит исходящий туннель к **мастеру L2X** и обеспечивает egress трафика клиентов панели:

```
VLESS/Trojan/… клиенты  →  Master (Xray + panel)  ↔  UDP tunnel  ↔  Agent (NAT node)  →  Internet
```

Критерий успеха: на канале ~1 Гбит/с агент даёт **≥850 Мбит/с direct** / **≥700 Мбит/с через релей** при CPU ≤70% ядра и RAM ≤150 МБ, без поломки существующих подписок и UI клиентов.

### 1.2. Роли (жёстко)

| Роль | Кто | Что делает |
|------|-----|------------|
| **End-user client** | Happ / v2rayN / … | Только обычные протоколы панели (VLESS и т.д.). **Не** говорит на протоколе туннеля. |
| **Master / coordinator** | Публичный сервер L2X | Terminate клиентских inbound; routing на `node_*`; control API; **туннельный peer** datapath; опциональный hole punch. |
| **Agent** | NAT-нода `nat=true`, `as_outbound=true` | Исходящий control + UDP data plane; локальный freedom/egress; **нет** публичных listener’ов для end-user. |

Hole punching выполняется **только** между **мастером и агентом** (оба серверные endpoint’ы). Punch «пользователь ↔ агент» — **вне скоупа**.

### 1.3. Вне скоупа v1

- Переписывание всей панели на Go (`TZ_GO.md`).
- L3 TUN / raw IP.
- Собственный congestion control с нуля (BBR/CUBIC с нуля запрещены).
- Hole punch до домашних/мобильных клиентов.
- Цель 10 Гбит/с.
- Замена WARP / обычных VLESS-outbound «маскарад» (они остаются параллельным путём).

### 1.4. Зачем это в L2X

Текущий NAT reverse (Xray portal + Mux + XHTTP через nginx) архитектурно режет throughput (особенно upload). Новый туннель — **замена datapath** для `node_*` reverse-outbound при сохранении:

- `/agent/pull`, `agent_token`, sync конфига;
- тегов outbound `node_<name>`;
- балансировщиков / групп клиентов / подписок.

---

## 2. Стыковка с панелью (~2000 учёток)

### 2.1. Модель нагрузки

| Понятие | Определение |
|---------|-------------|
| **Учётка** | Запись клиента в store (лимиты, sub token). |
| **Онлайн** | Клиент с активными соединениями к inbound мастера. |
| **Tunnel stream** | Один L4-поток внутри UDP-туннеля (обычно один TCP dial с мастера). |
| **Активный юзер** | Даёт N TCP streams (часто 5–50), не «1 сессия = 1 юзер». |

**Правило capacity:** один агент 1/1/40 рассчитан на **~100–300 активных** юзеров / **~2–4k concurrent streams** / **до ~1 Гбит** aggregate — **не** на все 2000 одновременно на одной ноде.

На **2000 учёток** обязательна **ферма нод** + существующие balancers (`lb_least_ping` / `lb_random` / группы). Оценка:

| Online (от 2000) | Активных | Нод 1/1 (ориентир) |
|------------------|----------|--------------------|
| 10% (200) | ~200 | 1–2 |
| 20% (400) | ~400 | 2–4 |
| 30% (600) | ~600 | 3–6 |

Мастер при 2000 юзерах нагружен сильнее агента (terminate VLESS **и** шифрование туннеля): **рекомендуется ≥2–4 vCPU / 2–4 ГБ**, не 1/1.

### 2.2. Интеграция с текущими сущностями

- Нода: `nat`, `as_outbound`, `agent_token` / pull — без ломки.
- Новый флаг режима: `tunnel_mode: xray_reverse | l2x_udp` (default на пилоте — opt-in `l2x_udp`).
- Outbound tag `node_*` на мастере указывает на **portal туннеля** (не VLESS reverse client), трафик Xray → tunnel dial → agent freedom.
- Health вместо/вместе с `rv_conns`: `tunnel_ok`, `tunnel_rtt_ms`, `tunnel_mbps`, `tunnel_streams`, `last_punch`.
- Мёртвый туннель: исключать tag из balancer selector; `fallback none` → `block` (как в v1.9.91+).

### 2.3. Путь трафика

```
Client ──VLESS──► Master Xray inbound
                     │
                     ▼
              routing → node_fi
                     │
                     ▼
           Master tunnel portal (UDP pool)
                     │
        ┌────────────┴────────────┐
        │ relay via master sock   │ direct after punch
        ▼                         ▼
   Agent UDP pool ◄───────────────┘
        │
        ▼
   local freedom / dial target
```

---

## 3. Целевые характеристики (агент 1/1/40)

Измерения на стенде 1 Гбит/с, MTU 1400–1500, payload с ChaCha20-Poly1305 (кроме колонки null).

| Параметр | Bulk (iperf-like) | Mixed web (много коротких TCP) |
|----------|-------------------|--------------------------------|
| Direct goodput | ≥ **850 Мбит/с** | ≥ **60%** от bulk при том же CPU-лимите |
| Relay goodput | ≥ **700 Мбит/с** | ≥ **55%** от bulk relay |
| CPU агента | ≤ **60–70%** одного ядра | ≤ **70–80%** (допустимо выше из‑за pps) |
| RAM агента | ≤ **120–150 МБ** steady | то же, без роста утечек |
| Установка туннеля | ≤ **2–3 с** после старта | — |
| Восстановление control | ≤ **3 с** | datapath без рестарта Xray на мастере |
| Concurrent streams | ≥ **2000–4000** | без OOM / thrash |
| Hole punch master↔agent | ≥ **80%** на UDP-friendly NAT | иначе стабильный relay; retry punch в фоне |

Отдельно документировать стенд с `cipher=null` (только lab) для оценки чистого framing overhead.

---

## 4. Функциональные требования

1. Исходящий постоянный control к мастеру (HTTPS pull/API + UDP keepalive/endpoint advertise).
2. Data plane: пул UDP-сокетов **4–8** (настраиваемо **1–16**).
3. Hole punch мастер↔агент; при успехе — direct path; иначе relay; периодический re-punch.
4. L4: TCP и UDP proxy (stream open с мастера → dial/forward на агенте).
5. Мультиплексирование многих streams поверх UDP-пула.
6. Аутентификация агента: существующий `agent_token` + отдельный tunnel PSK/сессионные ключи после handshake.
7. Шифрование: ChaCha20-Poly1305 по умолчанию; `cipher=null` только для бенчмарка.
8. Авто-reconnect control и datapath; seamless fallback direct→relay для живых streams (best-effort без обрыва TCP на стороне клиента: буфер/retry на мастере).
9. Control-команды: register, open/close stream, publish ports/limits, stats, keepalive, punch offer/answer.
10. Метрики: Prometheus-текст или JSON для панели (`streams`, `bps`, `rtt`, `loss`, `path=direct|relay`).

---

## 5. Архитектура агента

```
┌──────────────────────────────────────────┐
│              l2x-tunnel-agent (Go)       │
│  ┌─────────────┐    ┌─────────────────┐  │
│  │ Control     │    │ Data Plane      │  │
│  │ HTTPS pull  │    │ UDP Pool 4–16   │  │
│  │ + UDP KA    │    │ encrypt/decrypt │  │
│  └─────────────┘    └────────┬────────┘  │
│  ┌───────────────────────────┴─────────┐ │
│  │ Session / Stream Mux + path picker  │ │
│  └───────────────────────────┬─────────┘ │
│  ┌───────────────────────────┴─────────┐ │
│  │ Egress: dial TCP/UDP / freedom      │ │
│  └─────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

На мастере — симметричный **portal** (отдельный бинарь `l2x-tunneld` или модуль рядом с панелью), который:

- принимает UDP от агентов;
- отдаёт Xray поток в tunnel stream (dokodemo / freedom reverse / internal dial API — деталь реализации этапа интеграции);
- инициирует punch.

Hot path: минимум аллокаций, без `fmt`/рефлексии, логи только atomic counters.

---

## 6. Протокол

### 6.1. Data frame (12–16 байт + AEAD tag)

| Поле | Размер | Описание |
|------|--------|----------|
| Ver+Type | 1 | версия и тип (DATA / ACK / PUNCH / KA / CTRL) |
| Flags | 1 | path id nibble, FIN/RST, … |
| StreamID | 4 | |
| Seq/Nonce | 4 | per-path seq; AEAD nonce = path‖seq |
| Length | 2 | длина ciphertext payload |
| Payload | N | |

Контрольные пакеты — отдельные Type, минимальный размер.

### 6.2. Paths

- N UDP sockets с разными source port.
- Исходящее: round-robin или sticky-by-StreamID (предпочтительно **sticky**, меньше reorder).
- Входящее: со всех sockets пула.
- Этап 1: статический пул; динамика — опционально позже.

### 6.3. Congestion control

**Запрещено** писать CC с нуля.

Порядок:

1. **Этап 1:** raw UDP + application window + token bucket (укладка в CPU/1G на чистой сети).
2. **Этап 2 (если нужны потери/WAN):** `quic-go` на **relay/control** path для loss recovery; direct path — raw UDP + window, без самописного BBR.

### 6.4. Безопасность

- Регистрация: Bearer `agent_token` (как сейчас) + tunnel handshake (PSK из store ноды).
- AEAD на data; anti-replay по (path_id, seq) window.
- Rate-limit register/punch на мастере.
- Логи без payload.

---

## 7. Hole punching (master ↔ agent)

1. Агент регистрируется; мастер видит observed UDP endpoints пула.
2. Мастер (или punch-сервис) рассылает обеим сторонам mapped addresses.
3. Обе стороны шлют PUNCH probes со всех sockets пула.
4. При подтверждённом двустороннем exchange — `path=direct`.
5. Timeout N секунд → остаёмся на relay; фоновый re-punch.
6. Цель успеха: **≥80%** на типичных серверных NAT/UDP-friendly; симметричный/CGNAT — **не** KPI провала продукта (KPI = стабильный relay ≥700 Mbps).

---

## 8. Требования к реализации Go (1/1/40)

- `sync.Pool` буферов кратных MTU.
- Мало горутин: worker pool / connection workers, не «горутина на каждый read+write безbound».
- `golang.org/x/crypto/chacha20poly1305`.
- Сборка: `-ldflags="-s -w"`; runtime `GOGC=50–100` при необходимости.
- Конфиг: один YAML/JSON + env (`L2X_TUNNEL_*`).
- systemd unit + install рядом с agent panel install.
- Бинарники: `l2x-tunnel-agent` (нода), `l2x-tunneld` (мастер portal) — имена фиксируем так.

---

## 9. Критерии приёмки

- [ ] Direct bulk ≥850 Mbps @ ChaCha, CPU ≤70%, RAM ≤150 MB на 1/1.
- [ ] Relay bulk ≥700 Mbps при тех же лимитах.
- [ ] Mixed-web бенч задокументирован; goodput ≥60% bulk (direct) без OOM.
- [ ] ≥2000 concurrent streams soak ≥1 ч.
- [ ] Punch master↔agent ≥80% на стенде UDP-friendly; fallback на relay без падения панели.
- [ ] 24h soak без утечки RAM (тренд RSS стабилен).
- [ ] Нода в режиме `l2x_udp` появляется как живой `node_*` в балансировщиках; мёртвая исключается.
- [ ] End-user подписки не требуют нового клиента.
- [ ] Документирован overhead и методика замера (iperf3 / внутренний bench).

---

## 10. Этапы разработки

1. **Wire + register + relay UDP echo** (агент ↔ portal), cipher null/ChaCha.
2. **UDP pool** + bulk bench CPU/RAM на 1/1.
3. **Punch master↔agent** + fallback direct↔relay.
4. **Stream mux + TCP/UDP L4** (open stream → dial).
5. **Интеграция в L2X:** `tunnel_mode`, health fields, Xray portal wiring, UI метрик ноды.
6. **Mixed-web + soak 24h**, тюнинг pools/GOGC.
7. **Пилот:** перевод выбранных NAT-нод с `xray_reverse` → `l2x_udp`; откат флагом.

---

## 11. Конфигурация агента (черновик)

```yaml
master_url: https://panel.example.com/secret-path
agent_token: "..."
node_id: "..."
tunnel:
  psk: "..."
  listen_udp: 0.0.0.0:0
  path_count: 8          # 1..16
  cipher: chacha20poly1305  # or null (lab only)
  punch_timeout_ms: 2500
  punch_interval_sec: 60
  max_streams: 4000
  max_mbps: 0            # 0 = unlimited; else token bucket
metrics:
  listen: 127.0.0.1:9109
```

Env перекрывает файл: `L2X_TUNNEL_MASTER_URL`, `L2X_TUNNEL_TOKEN`, …

---

## 12. Риски и слабые места (учтены в KPI)

| Риск | Митигация в ТЗ |
|------|----------------|
| Путать end-user с tunnel client | Роли зафиксированы; punch только master↔agent |
| «200–300 сессий» = юзеры | Метрики streams/Mbps; capacity-таблица |
| Мастер 1/1 при 2000 | Рекомендация ≥2–4 vCPU на master |
| ChaCha + high pps | Отдельный mixed-web KPI |
| Punch &lt;90% на плохом NAT | KPI 80% + обязательный relay ≥700 |
| Mux head-of-line | Sticky StreamID→path; пул сокетов |
| Утечки goroutine/buffer | Soak 24h + pool discipline |

---

## 13. Критерий «всё работает отлично» для продукта

1. NAT-нода 1/1 стабильно отдаёт ≥0.7–0.85G без Xray reverse.
2. 2000 учёток обслуживаются **пулом** таких нод через существующие balancers/groups.
3. Админ видит health туннеля в карточке ноды и может переключить `tunnel_mode` без смены клиентских приложений.
4. При падении туннеля трафик не утекает в `direct` при `fallback=none`.
