## v2.2.13 — PasarGuard: HWID devices, limits, dates, traffic

Import from backup now also transfers:
- ``hwid_limit`` → ``limit_hwid``
- ``user_hwids`` (bound devices: hash, OS, model, first/last seen)
- traffic usage (``used_traffic`` / lifetime)
- ``created_at`` / ``updated_at`` / ``online_at``
- ``data_limit_reset_strategy`` → ``reset_period``

Re-import the PasarGuard backup to fill devices on already-migrated clients.
