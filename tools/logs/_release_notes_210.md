## Changes
- **Ядра 2.1** — паритет с PasarGuard CoreConfig
- Поля: `exclude_inbound_tags`, `fallbacks_inbound_tags`, JSON `config`, `statsUserOnline`, loglevel
- Страница настроек ядра + валидация тегов/портов/Reality по доке PasarGuard
- Режим правки срезов: Inbounds / Outbounds / Маршруты / DNS редактируются в контексте ядра
- Default-ядро нельзя удалить; дублирование, Sync всех нод ядра
- Sync учитывает exclude/fallback и overlay config

Обновление из панели → **v2.1.0**.
