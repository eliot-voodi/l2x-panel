## v2.3.9 — Reality + Mihomo (stable path)

- Keep Xray **26.11.9** on Reality nodes with Clash `support-x25519mlkem768: true` + `chrome` (only combo where Mihomo auth succeeds)
- Do **not** pin ≤26.7.28 for “classical” — Mihomo still fails Reality auth there; Xray clients OK
- Clash YAML: `profile-update-interval: 1`; wider Clash UA sniff (verge/koala/party/…)
- Note: from RU, hybrid Reality ClientHello may be DPI-blocked — NL grpc/ws/rality-vk stay the reliable path
