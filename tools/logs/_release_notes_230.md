## v2.3.0 — PostgreSQL + ускорение панели

### Скорость (фаза 0)
- **In-memory кэш** `store.json` — повторные чтения вкладок без parse ~4 МБ (cached ~0 мс)
- **Компактный JSON** (без indent) при сохранении
- **История версий**: `MAX_VERSIONS=30`, prune сирот (~1.25 ГБ → ~125 МБ), slim-снимки для правок клиентов
- **Apply в фоне**: сохранение клиента/группы и sync нод не блокируют браузер; Apply ядра — sync нод в job
- Кэш `xray_status` ~2 с

### PostgreSQL (фаза 1–2)
- Postgres 16/17 на master; `L2XPANEL_DATABASE_URL` через `/etc/l2xpanel/postgres.env`
- Таблицы: `panel_store` (полный jsonb), `clients`, `groups`, `client_hwids`, `client_traffic`, `settings_versions`
- Автоимпорт `store.json` → PG при старте; файл остаётся compact backup
- Бэкап zip включает `postgres/l2xpanel.sql` (`pg_dump`)

Контракт sync с агентами не менялся — только хранилище мастера.
