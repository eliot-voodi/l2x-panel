## v2.2.11 — PasarGuard migrate: groups → users → assign

### Groups not assigned after migrate
Preview→Import dropped ``group_names`` from the migrate cache, so groups were
created but clients kept empty ``group_id`` (and fell into «all inbounds»).

### Fix
1. Cache round-trip keeps ``groups`` / ``group_names`` / ``group_ids``.
2. Import order: create groups → upsert users → assign ``group_id`` (clears personal inbounds).
3. Re-attach names from ``users_groups`` meta before assign (id key variants).
4. Guard: scrub duplicate emails in built Xray config (``email~node_* already exists``).
