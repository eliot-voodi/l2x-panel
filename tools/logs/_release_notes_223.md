## v2.2.3 — Ascella cascade Custom JSON + Apply auto-regen + correct node host

- Client JSON uses **Ascella cascade** again (LOOP / REROUTE / leastLoad per inbound) — not a flat leastPing of all tags
- Custom JSON profiles dial **all core inbounds** (not only the client's checked ones), so cascade and `subjectSelector` stay complete when you add a new inbound
- `subjectSelector` = inbound tags; each cascade balancer selects one outbound
- Core routes with outbound `client` still inject as `direct` (bypass VPN)
- When several Direct nodes share one core, host is picked by name/domain match (Amsterdam → `am.ro0t.dev`, not `buh`)
- **Применить** on a core auto-regenerates Custom JSON from all inbounds
- Reality+TCP without flow → `xtls-rprx-vision` in client JSON
