## v2.2.14 — PasarGuard migrate extras + required fields *

### Migrate (PasarGuard)
- **Inbounds групп** (`inbounds_groups_association`) → ядра L2X, покрывающие эти tag’и
- **Несколько групп** на пользователя → объединённая группа (union cores)
- **Шаблоны** (`user_templates`) → группы-пресеты «Шаблон: …»
- **on_hold** → `start_on_first_use` + `duration_days` из `on_hold_expire_duration`
- **next_plan** → `on_expire=renew` / `renew_on_reset` + длительность
- **Админ-владелец** → поле `admin` у клиента
- `auto_delete_in_days` → `on_expire=delete`

Не переносятся: usage-логи, node usages, hosts/ноды/inbounds инфраструктуры PG.

### UI
- Красная `*` у обязательных полей на создании/редактировании
- Проверка заполненности при submit (подсветка + alert)
