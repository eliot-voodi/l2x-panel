# L2X Panel — REST API

Полное описание программного интерфейса панели: REST API для автоматизации (боты, биллинг, CRM), подписки для клиентских приложений, вебхуки и протокол синхронизации нод.

- [Общие сведения](#общие-сведения)
  - [Базовый URL](#базовый-url)
  - [Аутентификация](#аутентификация)
  - [Формат ответа и ошибки](#формат-ответа-и-ошибки)
- [Объекты](#объекты)
  - [Client](#client)
  - [Inbound](#inbound)
  - [Outbound-теги](#outbound-теги)
- [Эндпоинты](#эндпоинты)
  - [Сервер](#сервер)
  - [Inbounds](#inbounds)
  - [Клиенты](#клиенты)
  - [HWID-устройства](#hwid-устройства)
  - [L2TP и outbounds](#l2tp-и-outbounds)
  - [Xray](#xray)
  - [Бэкап](#бэкап)
- [Подписки](#подписки)
- [Вебхуки](#вебхуки)
- [Синхронизация нод (agent API)](#синхронизация-нод-agent-api)
- [Служебные эндпоинты](#служебные-эндпоинты)
- [Примеры](#примеры)

---

## Общие сведения

### Базовый URL

```
http://<host>/panel/api/
```

`<host>` — адрес панели (IP или домен). Путь `/panel/api/` **не зависит** от секретного пути панели (Settings → Panel → base path): API, подписки и `/health` всегда доступны по корню.

### Аутентификация

API принимает любой из способов:

| Способ | Пример |
|---|---|
| Bearer-токен | `Authorization: Bearer l2x_xxxxxxxx` |
| Заголовок API-ключа | `X-API-Key: l2x_xxxxxxxx` |
| Сессия панели | cookie `session` после входа в веб-интерфейс |

Токены создаются в **Settings → API** (кнопка «Создать токен»). Полное значение показывается один раз; в базе хранится только SHA-256 хеш. Удалённый токен перестаёт работать сразу.

Без авторизации любой эндпоинт возвращает `401`:

```json
{"success": false, "msg": "unauthorized"}
```

### Формат ответа и ошибки

Все ответы — JSON в едином конверте:

```json
{"success": true, "msg": "", "obj": { ... }}
```

| Поле | Тип | Описание |
|---|---|---|
| `success` | bool | `true` — запрос выполнен |
| `msg` | string | Пояснение. При успешном изменении клиента может содержать текст ошибки применения конфига Xray |
| `obj` | any | Полезная нагрузка (объект, массив или `null`) |

Ошибки возвращаются с HTTP-кодом `4xx` и `success: false`:

| Код | `msg` | Когда |
|---|---|---|
| 400 | `bad json` | тело POST не является JSON |
| 400 | `bad or duplicate email` | некорректный или уже существующий email |
| 400 | `unknown outbound <tag>` | указан несуществующий outbound |
| 400 | `bad expire_at` | дата не распознана |
| 401 | `unauthorized` | нет или неверный токен |
| 404 | `not found` | клиент или inbound не найден |
| 404 | `unknown endpoint` | неизвестный путь или метод |

POST-запросы должны иметь `Content-Type: application/json`. Если заголовок другой, тело игнорируется.

---

## Объекты

### Client

Объект клиента, который возвращают `clients/list`, `clients/get`, `clients/add`, `clients/update`:

```json
{
  "email": "alice",
  "uuid": "6f1c5b0e-3a52-4c1e-9a43-7f1f0b9a2c11",
  "enabled": true,
  "status": "active",
  "outbound": "lb_least_ping",
  "inbounds": ["vless-in", "hy2-in"],
  "limit_gb": 50,
  "expire_at": "2026-12-31T23:59:59+00:00",
  "limit_ip": 2,
  "limit_hwid": 3,
  "hwid": {"active": true, "limit": 3, "registered": 1, "remaining": 2, "full": false},
  "up": 104857600,
  "down": 2147483648,
  "online": true,
  "last_online": "2026-11-04T20:31:12+00:00",
  "comment": "VIP",
  "tg_id": "123456789",
  "sub_url": "https://vpn.example.com:2096/sub/eWnpMHl8KeGqmSHInxpFNTSx",
  "reset_period": "monthly",
  "outbound_limits": {"l2tp_germany": 20},
  "allowed_tags": []
}
```

| Поле | Тип | Запись | Описание |
|---|---|---|---|
| `email` | string | только при создании | Уникальный идентификатор клиента. Допустимо: `name@domain` или `[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}` |
| `uuid` | string | при создании | UUID для VLESS/VMess. Генерируется, если не передан |
| `enabled` | bool | да | Выключенный клиент удаляется из конфига Xray |
| `status` | string | нет | `active`, `disabled`, `expired` (истёк срок), `limited` (исчерпан трафик) |
| `outbound` | string | да | Outbound по умолчанию для трафика клиента. См. [Outbound-теги](#outbound-теги). По умолчанию `direct` |
| `inbounds` | string[] | да | Теги inbounds, в которые добавлен клиент. `[]` — во все inbounds, поддерживающие клиентов |
| `limit_gb` | number | да | Лимит трафика (up + down) в ГБ. `0` — без лимита |
| `expire_at` | string | да | Срок действия: `YYYY-MM-DD` (до 23:59:59 UTC) или ISO 8601. `""` — бессрочно |
| `limit_ip` | int | да | Максимум одновременных IP. `0` — без лимита. Превышение банит лишние IP |
| `limit_hwid` | int | да | Максимум HWID-устройств для подписки. `0` — без лимита |
| `hwid` | object | нет | Состояние HWID: `active`, `limit`, `registered`, `remaining` (`null` без лимита), `full` |
| `up`, `down` | int | нет | Использованный трафик, байты |
| `online` | bool | нет | Есть активные подключения прямо сейчас |
| `last_online` | string | нет | Время последней активности (ISO 8601) |
| `comment` | string | да | Произвольный комментарий |
| `tg_id` | string | да | Telegram ID клиента (для бота) |
| `sub_url` | string | нет | Ссылка на подписку |
| `reset_period` | string | да | Автосброс трафика: `""`, `daily`, `weekly`, `monthly` |
| `outbound_limits` | object | да | Лимиты по отдельным outbound: `{"<tag>": <ГБ>}` |
| `allowed_tags` | string[] | да | Разрешённые outbounds в подписке. `[]` — все |

Поля, которые можно передать в `clients/add` и `clients/update`, но которые не возвращаются в объекте:

| Поле | Тип | Описание |
|---|---|---|
| `renew_on_reset` | bool | При автосбросе продлевать `expire_at` на тот же период |
| `start_on_first_use` | bool | Срок начинает идти с первого подключения |
| `duration_days` | int | Длительность в днях для `start_on_first_use` |
| `sub_enabled` | bool | Отдавать ли подписку клиенту (по умолчанию `true`) |

### Inbound

Объект inbound возвращается как есть из базы (`inbounds/list`, `inbounds/get`) с дополнительным полем `used`:

```json
{
  "id": 1,
  "tag": "vless-in",
  "remark": "VLESS Reality",
  "enabled": true,
  "listen": "0.0.0.0",
  "port": 443,
  "protocol": "vless",
  "settings": {"decryption": "none", "flow": "xtls-rprx-vision"},
  "stream": {"network": "raw", "security": "reality", "reality": {"dest": "www.microsoft.com:443", "...": "..."}},
  "sniffing": {"enabled": true, "dest": ["http", "tls", "quic"], "route_only": false, "metadata_only": false},
  "fallbacks": [],
  "outbound": "direct",
  "share_host": "",
  "total_gb": 0,
  "expire_at": "",
  "traffic": {"up": 0, "down": 0, "last_up": 0, "last_down": 0},
  "used": 0
}
```

Протоколы: `vless`, `vmess`, `trojan`, `shadowsocks`, `hysteria` (Hysteria2), `wireguard`, `socks`, `http`, `dokodemo-door`.
Транспорты (`stream.network`): `raw`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `kcp`, `hysteria`.
Безопасность (`stream.security`): `none`, `tls`, `reality`.

### Outbound-теги

Поле `outbound` клиента и ключи `outbound_limits` / `allowed_tags` принимают теги:

| Тег | Что это |
|---|---|
| `direct` | Выход напрямую с сервера |
| `block` | Блокировать трафик |
| `l2tp_<name>` | L2TP-туннель с именем `<name>` (страница L2TP) |
| `lb_least_ping` | Балансировщик по минимальному пингу между туннелями |
| `lb_least_load` | Балансировщик по наименьшей нагрузке |
| `<custom>` | Пользовательские outbounds (WireGuard, WARP, NordVPN, PIA, VLESS / VMess / Trojan / Shadowsocks, SOCKS, HTTP) |

### DoH (Pi-hole)

Публичный персональный endpoint (через nginx :443):

`https://<domain>/doh/<token>/dns-query` — RFC 8484 (GET `?dns=` / POST `application/dns-message`).

В карточке клиента: `doh_enabled`, `doh_in_tunnel` (DNS в подписке через proxy). Управление: UI **DoH / Pi-hole**.

Актуальный список — `GET outbounds/list` → `obj.tags`.

---

## Эндпоинты

Все пути ниже указаны относительно `/panel/api/`.

| Метод | Путь | Описание |
|---|---|---|
| GET | [`server/status`](#get-serverstatus) | Состояние сервера и Xray |
| GET | [`inbounds/list`](#get-inboundslist) | Все inbounds |
| GET | [`inbounds/get/{id}`](#get-inboundsgetid) | Один inbound |
| GET | [`inbounds/onlines`](#get-inboundsonlines) | Клиенты онлайн |
| GET | [`clients/list`](#get-clientslist) | Все клиенты |
| GET | [`clients/get/{email}`](#get-clientsgetemail) | Один клиент |
| POST | [`clients/add`](#post-clientsadd) | Создать клиента |
| POST | [`clients/update/{email}`](#post-clientsupdateemail) | Изменить клиента |
| POST, DELETE | [`clients/delete/{email}`](#post-clientsdeleteemail) | Удалить клиента |
| POST, DELETE | [`clients/reset/{email}`](#post-clientsresetemail) | Сбросить трафик клиента |
| POST | [`clients/resetAll`](#post-clientsresetall) | Сбросить трафик всех клиентов |
| GET | [`clients/{email}/hwids`](#get-clientsemailhwids) | HWID-устройства клиента |
| DELETE | [`clients/{email}/hwids`](#delete-clientsemailhwids) | Сбросить HWID-устройства |
| GET | [`l2tp/list`](#get-l2tplist) | L2TP-туннели |
| GET | [`outbounds/list`](#get-outboundslist) | Outbounds, трафик и скорость |
| POST | [`xray/restart`](#post-xrayrestart) | Перезапустить Xray |
| GET | [`xray/config`](#get-xrayconfig) | Итоговый `config.json` Xray |
| GET | [`backup`](#get-backup) | Скачать zip-бэкап |

### Сервер

#### `GET server/status`

Нагрузка сервера, состояние Xray и число клиентов онлайн.

```json
{
  "success": true, "msg": "",
  "obj": {
    "cpu": 7.5,
    "cores": 2,
    "load": [0.12, 0.08, 0.05],
    "mem": {"total": 2063437824, "used": 612368384, "swap_total": 0, "swap_used": 0},
    "disk": {"total": 21003628544, "used": 6103482368},
    "uptime": 864000,
    "net": {"iface": "eth0", "rx": 98234123412, "tx": 97123412341, "rx_s": 1250000.0, "tx_s": 1180000.0},
    "conns": {"tcp": 412, "udp": 37},
    "xray": {"active": true, "state": "active", "version": "26.10.31"},
    "online": 14
  }
}
```

`mem`, `disk` и `net.rx`/`net.tx` — в байтах; `net.rx_s`/`net.tx_s` — байт/с; `uptime` — секунды.

### Inbounds

#### `GET inbounds/list`

Массив [Inbound](#inbound) с полем `used` (байты, up + down).

#### `GET inbounds/get/{id}`

Один inbound по числовому `id`. `404`, если не найден.

#### `GET inbounds/onlines`

Клиенты онлайн и их IP-адреса:

```json
{"success": true, "msg": "", "obj": {"alice": ["203.0.113.5"], "bob": ["198.51.100.7", "198.51.100.8"]}}
```

### Клиенты

#### `GET clients/list`

Массив [Client](#client).

#### `GET clients/get/{email}`

Один [Client](#client). `404`, если не найден.

#### `POST clients/add`

Создаёт клиента и применяет конфиг Xray. Обязательно только `email`; остальные поля — из таблицы [Client](#client).

```bash
curl -s -X POST "http://$HOST/panel/api/clients/add" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
        "email": "alice",
        "outbound": "lb_least_ping",
        "limit_gb": 50,
        "expire_at": "2026-12-31",
        "limit_ip": 2,
        "limit_hwid": 3,
        "reset_period": "monthly",
        "comment": "VIP"
      }'
```

Ответ — созданный [Client](#client), включая `uuid` и `sub_url`. Если Xray не принял новый конфиг, клиент всё равно создаётся, а текст ошибки приходит в `msg`.

#### `POST clients/update/{email}`

Частичное обновление: передавайте только изменяемые поля. `email` изменить нельзя.

```bash
# продлить на месяц и увеличить лимит
curl -s -X POST "http://$HOST/panel/api/clients/update/alice" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"expire_at": "2027-01-31", "limit_gb": 100, "enabled": true}'
```

Ответ — обновлённый [Client](#client).

#### `POST clients/delete/{email}`

Также принимает `DELETE`. Удаляет клиента и применяет конфиг.

```json
{"success": true, "msg": "delete ok", "obj": null}
```

#### `POST clients/reset/{email}`

Также принимает `DELETE`. Обнуляет трафик клиента и снимает флаги превышения лимитов.

```json
{"success": true, "msg": "reset ok", "obj": null}
```

#### `POST clients/resetAll`

Обнуляет трафик всех клиентов.

```json
{"success": true, "msg": "reset all", "obj": null}
```

### HWID-устройства

HWID-устройства регистрируются, когда клиентское приложение (Happ, v2RayTun, Hiddify и т. п.) запрашивает подписку с заголовком `X-HWID`. Подробнее — в разделе [Подписки](#hwid).

#### `GET clients/{email}/hwids`

```json
{
  "success": true, "msg": "",
  "obj": [
    {
      "fp": "3f9a1c0b2d4e",
      "kind": "hwid",
      "first_seen": "2026-11-04T20:31:12+00:00",
      "last_seen": "2026-11-05T08:02:44+00:00",
      "ua": "Happ/3.2.1",
      "os": "Android",
      "os_ver": "15",
      "model": "Pixel 8"
    }
  ]
}
```

`fp` — первые 12 символов SHA-256 от HWID (или от запасного отпечатка). Исходный HWID не хранится.

`kind` — как определено устройство: `hwid` — по заголовку `X-HWID`; `device` — по приложению, ОС и модели; `ua` — только по приложению (неточно). См. [HWID](#hwid).

#### `DELETE clients/{email}/hwids`

Удаляет все зарегистрированные устройства клиента. После этого первые `limit_hwid` устройств, обновивших подписку, зарегистрируются заново.

```json
{"success": true, "msg": "", "obj": {"cleared": 2}}
```

### L2TP и outbounds

#### `GET l2tp/list`

L2TP-туннели без паролей:

```json
{
  "success": true, "msg": "",
  "obj": [
    {
      "name": "germany",
      "server_host": "de.vpn.example.net",
      "username": "user1",
      "password_set": true,
      "psk_set": true,
      "status": "connected",
      "outbound": "l2tp_germany",
      "ifname": "l2x-germany",
      "addr": "10.10.0.15",
      "local_ip": "10.10.0.15",
      "peer_ip": "10.10.0.1",
      "country": "DE",
      "last_error": ""
    }
  ]
}
```

`status`: `connected`, `disconnected`, `error`. Набор дополнительных полей зависит от состояния туннеля. Пароль и PSK хранятся отдельно в зашифрованном виде и через API не отдаются.

#### `GET outbounds/list`

Теги outbounds, накопленный трафик и скорость:

```json
{
  "success": true, "msg": "",
  "obj": {
    "tags": ["direct", "block", "l2tp_germany", "warp", "lb_least_ping", "lb_least_load"],
    "traffic": {"l2tp_germany": {"up": 1048576, "down": 73400320}},
    "rates": {"l2tp_germany": {"up": 12000, "down": 845000}},
    "summary_1h": {"l2tp_germany": {"avg_up": 9000.5, "avg_down": 640000.2, "peak_up": 52000, "peak_down": 3100000}},
    "summary_24h": {"l2tp_germany": {"avg_up": 4000.1, "avg_down": 310000.7, "peak_up": 88000, "peak_down": 5400000}}
  }
}
```

- `traffic` — байты с момента последнего сброса;
- `rates` — текущая скорость, байт/с (замер раз в ~20 с);
- `summary_1h` / `summary_24h` — средняя и пиковая скорость по минутным точкам, байт/с.

### Xray

#### `POST xray/restart`

```json
{"success": true, "msg": "", "obj": {"ok": true, "code": 0, "stdout": "", "stderr": ""}}
```

#### `GET xray/config`

Итоговый `config.json`, который панель генерирует для Xray (inbounds, outbounds, routing, balancers, DNS, policy, stats API).

### Бэкап

#### `GET backup`

Возвращает `application/zip` (не JSON) со всеми данными панели: `store.json`, `admin.json`, ключи, L2TP-профили. Восстановление — в веб-интерфейсе (Settings → Backup).

```bash
curl -s -H "Authorization: Bearer $TOKEN" -o l2x-backup.zip "http://$HOST/panel/api/backup"
```

---

## Подписки

Подписки публичные, авторизация — секретный токен в пути.

| Вариант | URL |
|---|---|
| Через панель (HTTP) | `http://<host>/sub/<token>` |
| Отдельный сервер подписок | `https://<domain-or-ip>:<port>/<path>/<token>` (по умолчанию порт `2096`, путь `sub`) |

Отдельный сервер включается в **Settings → Subscriptions**. Для HTTPS выберите сертификат, выпущенный в **Settings → Certificates** (Let's Encrypt на домен или IP). Актуальную ссылку клиента возвращает поле `sub_url`.

### Форматы

| Формат | Как выбрать | Содержимое |
|---|---|---|
| base64 | по умолчанию | Ссылки `vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://` в base64 |
| plain | `?format=plain` | Те же ссылки обычным текстом |
| json | `?format=json` | Массив полных клиентских конфигов Xray (+ Fragment/Noise/Mux из настроек) |
| clash | `?format=clash` или User-Agent `clash`/`mihomo`/`stash` | YAML для Clash Meta / Mihomo |
| sing-box | `?format=singbox` или User-Agent `sing-box`/`SFA`/`SFI` | JSON для sing-box |
| html | браузер (`Accept: text/html`) | Страница клиента: трафик, срок, QR-коды, ссылки |

### Заголовки ответа

| Заголовок | Значение |
|---|---|
| `profile-title` | Название профиля (`base64:...`) |
| `profile-update-interval` | Интервал автообновления, часы |
| `subscription-userinfo` | `upload=…; download=…; total=…; expire=<unix>` |
| `support-url` | Ссылка поддержки (если задана) |
| `announce` | Объявление (`base64:...`, если задано) |
| `providerid` | Happ Provider ID (если задан) |
| `subscription-always-hwid-enable` | `1`, если включён «Обязательный HWID» |
| `new-url` | Актуальный адрес подписки, если клиент пришёл по старому адресу и включён перенос адреса |
| `X-Hwid-*` | Состояние HWID (см. ниже) |

### Коды ответа

| Код | Причина |
|---|---|
| 200 | Подписка выдана |
| 403 | Клиент выключен, истёк срок или исчерпан трафик (тело — статус клиента) |
| 404 | Неверный токен, подписки выключены или не пройдена HWID-проверка |

### HWID

HWID-проверка применяется к машинным форматам (не к HTML-странице):

- у клиента задан `limit_hwid > 0` — разрешено не больше `limit_hwid` устройств;
- в настройках включён **«Обязательный HWID»** — подписка не выдаётся без заголовка `X-HWID`, даже при `limit_hwid = 0`.

Приложение передаёт заголовки `X-HWID` (не короче 6 символов), `X-Device-OS`, `X-Ver-OS`, `X-Device-Model`, `User-Agent`.

Если `X-HWID` нет и «Обязательный HWID» выключен, устройство считается по запасному отпечатку. Режим задаётся настройкой «Приложения без X-HWID» (`settings.sub.hwid_fallback`):

| Режим | Отпечаток | Когда не хватает заголовков |
|---|---|---|
| `device` (по умолчанию) | имя приложения из `User-Agent` без версии + `X-Device-OS` + `X-Device-Model` | нет ни ОС, ни модели → `404` |
| `ua` | как `device`; без ОС и модели — только имя приложения | нет `User-Agent` приложения → `404` |
| `off` | не используется | всегда `404` |

Отпечаток привязан к клиенту (токену подписки). Браузеры и HTTP-библиотеки (`Mozilla`, `curl`, `okhttp` …) приложением не считаются.

| Ситуация | Ответ |
|---|---|
| HWID-проверка выключена | `200`, `X-Hwid-Active: false` |
| `X-HWID` короче 6 символов | `404`, `X-Hwid-Not-Supported: true` |
| Нет `X-HWID`, и запасного отпечатка не хватает | `404`, `X-Hwid-Not-Supported: true` |
| Известное устройство или есть свободный слот | `200`, устройство регистрируется |
| Лимит устройств исчерпан | `404`, `X-Hwid-Max-Devices-Reached: true`, вебхук `client.hwid_full` |

Happ выполняет `subscription-always-hwid-enable` и `new-url` только при заданном Provider ID (`happ-proxy.com`). Серверная HWID-проверка работает без него.

---

## Вебхуки

Настраиваются в **Settings → Webhooks**: список URL, секрет и набор событий. Панель отправляет `POST` с JSON:

```http
POST /your/endpoint HTTP/1.1
Content-Type: application/json
User-Agent: L2XPanel-Webhook/1.0
X-L2X-Secret: <secret>

{
  "event": "client.hwid_full",
  "ts": "2026-11-05T08:02:44+00:00",
  "data": {"email": "alice", "limit": 3}
}
```

Проверяйте заголовок `X-L2X-Secret` на своей стороне. Доставка выполняется в фоне, таймаут 8 с, без повторов.

| Событие | `data` |
|---|---|
| `login` | `{"user": "admin", "ip": "203.0.113.5"}` — успешный вход в панель |
| `client.deleted` | `{"email": "alice"}` |
| `client.hwid_full` | `{"email": "alice", "limit": 3}` — новое устройство отклонено по лимиту |
| `node.sync` | `{"node": "nl-1", "ok": true, "error": null}` — результат синхронизации ноды |

Зарезервированы и пока не отправляются: `client.created`, `client.updated`, `client.expired`, `client.limited`, `tunnel.up`, `tunnel.down`, `backup`.

---

## Синхронизация нод (agent API)

Мастер-панель может рассылать клиентов и конфигурацию на другие серверы с L2X Panel.

1. На **ноде**: Settings → Nodes → включить агент и скопировать токен.
2. На **мастере**: страница Nodes → добавить ноду (URL панели ноды и токен).
3. «Синхронизировать» отправляет конфигурацию на `POST <url>/agent/apply`.

#### `POST /agent/apply`

Путь от корня ноды. Если на ноде задан секретный путь панели, укажите его в URL ноды: `http://node/<secret>`.

```http
POST /agent/apply HTTP/1.1
Authorization: Bearer <agent_token>
Content-Type: application/json

{
  "clients": [ ... ],
  "inbounds": [ ... ],
  "outbounds_custom": [ ... ],
  "routes": [ ... ],
  "balancers": { ... },
  "dns": { ... },
  "xray_settings": { ... },
  "config": { ... },
  "pushed_at": "2026-11-05T08:00:00+00:00",
  "node_id": "5d1f..."
}
```

Каждый переданный ключ (кроме `config`, `pushed_at`, `node_id`) заменяет соответствующий раздел базы ноды; отсутствующие ключи не трогаются. L2TP-outbounds мастера на ноде превращаются в `freedom`: L2TP-интерфейсов там нет.

| Код | Ответ |
|---|---|
| 200 | `{"ok": true, "error": ""}` |
| 400 | `{"ok": false, "error": "bad json"}` |
| 401 | `{"ok": false, "error": "unauthorized"}` |
| 403 | `{"ok": false, "error": "agent disabled"}` |

---

## Служебные эндпоинты

| Метод | Путь | Авторизация | Описание |
|---|---|---|---|
| GET | `/health` | нет | `{"status": "ok", "app": "L2X Panel", "time": "..."}` — для мониторинга |
| GET | `/api/status` | сессия | То же, что `server/status`, плюс `ob_rates` |
| GET | `/api/history?n=360` | сессия | Минутные точки нагрузки сервера для графиков |
| GET | `/api/outbounds?tag=<tag>&n=60` | сессия | Ряд скорости outbound (`[{"t", "up", "down"}]`), без `tag` — сумма |
| GET | `/api/keys/wg[?private=<key>]` | сессия | Новая пара ключей WireGuard или публичный ключ для приватного |
| GET | `/jobs/{job_id}` | сессия | Статус фоновой задачи (выпуск сертификата, обновление Xray) |

Эндпоинты с авторизацией «сессия» используются веб-интерфейсом и не принимают API-токены.

---

## Примеры

### Python

```python
import requests

HOST = "http://203.0.113.10"
s = requests.Session()
s.headers["Authorization"] = "Bearer l2x_xxxxxxxx"

def api(method: str, path: str, **kw):
    r = s.request(method, f"{HOST}/panel/api/{path}", timeout=30, **kw)
    data = r.json()
    if not data["success"]:
        raise RuntimeError(f"{r.status_code}: {data['msg']}")
    return data["obj"]

client = api("POST", "clients/add", json={"email": "alice", "limit_gb": 50, "expire_at": "2026-12-31"})
print(client["sub_url"])

api("POST", "clients/update/alice", json={"limit_gb": 100})

for c in api("GET", "clients/list"):
    print(c["email"], c["status"], (c["up"] + c["down"]) / 2**30, "GB")
```

### JavaScript (Node 18+)

```js
const HOST = "http://203.0.113.10";
const TOKEN = "l2x_xxxxxxxx";

async function api(method, path, body) {
  const res = await fetch(`${HOST}/panel/api/${path}`, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!data.success) throw new Error(`${res.status}: ${data.msg}`);
  return data.obj;
}

const client = await api("POST", "clients/add", { email: "bob", limit_gb: 30, limit_hwid: 2 });
console.log(client.sub_url);
```

### Продление подписки после оплаты (bash)

```bash
#!/usr/bin/env bash
# usage: extend.sh <email> <days>
set -euo pipefail
HOST=http://203.0.113.10
TOKEN=l2x_xxxxxxxx
EMAIL=$1; DAYS=$2

current=$(curl -fsS -H "Authorization: Bearer $TOKEN" "$HOST/panel/api/clients/get/$EMAIL" | jq -r '.obj.expire_at')
base=$(date -u +%Y-%m-%d)
[ -n "$current" ] && [ "$(date -u -d "$current" +%s)" -gt "$(date -u +%s)" ] && base=$(date -u -d "$current" +%Y-%m-%d)
new=$(date -u -d "$base + $DAYS days" +%Y-%m-%d)

curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"expire_at\": \"$new\", \"enabled\": true}" \
  "$HOST/panel/api/clients/update/$EMAIL" | jq '.obj | {email, expire_at, status}'
```
