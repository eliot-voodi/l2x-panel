## v2.2.12 — Parse PasarGuard `users_groups_association`

Groups were created on migrate but never assigned: membership lives in
``users_groups_association(user_id, groups_id)``, not ``users_groups``.

### Fix
- Recognize ``users_groups_association`` (COPY + INSERT) and SQLite equivalents
- Prefer ``groups_id`` column name used by PasarGuard SQLAlchemy
- Parse Postgres ``{1,2,3}`` group_ids arrays on users as fallback
- Preview warns when groups exist but user↔group links = 0

Re-import the PasarGuard backup (Проверить → Импорт) to assign ``group_id``.
