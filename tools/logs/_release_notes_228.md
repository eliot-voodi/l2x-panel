## v2.2.8 — Migration: groups instead of inbounds (PasarGuard groups)

- Migrate UI: choose an L2X **group** (fallback), not inbound checkboxes
- PasarGuard: create the same groups from backup/API (`groups` + `users_groups`) and assign them to users
- Imported groups are empty (`core_mode=select`, no cores) — assign cores later in Группы
- Empty select-group does not grant all inbounds until cores are chosen
