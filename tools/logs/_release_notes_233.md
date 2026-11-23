## v2.2.10 — Fix Direct sync `User email~node_* already exists`

After PasarGuard migration, multi-inbound Direct cores (Buharest/yandex/vk, …) failed to start Xray on agents:

`User roma-ko~node_1234 already exists`

### Cause
1. Same `email~node_*` identity was registered on every inbound of the core.
2. On agents ≤2.2.8, `_agent_safe_clients` also appended `self_tag` to `allowed_tags`, so `subscription_entries` emitted the **same** email again inside one inbound (`local_direct` had `in_sub=True`).

### Fix
- Master `build_config`: uniquify emails across inbounds.
- Direct payload: split each client to one inbound (suffix email for 2nd+), clear `group_id`.
- `_local_direct_outbound`: `in_sub=False` so old agents no longer double-register `email~node_*`.
- Stop auto-append of `self_tag` to `allowed_tags` (already in tree).
