## v2.4.0 — Mihomo from RU: drop Reality, TLS front

- Reality nodes (Russia / Buharest / yandex / vk.ru / pol-vk) published as **VLESS + TLS** (raw or WS behind nginx) — same pattern as Amsterdam `rality-vk`
- Reason: Mihomo + Xray ≥26.9.8 Reality needs hybrid ML-KEM ClientHello; RU DPI often blocks it → only NL grpc/ws worked
- Clash: Reality ML-KEM export kept for any remaining Reality; cosmetic `/u-…` WS paths disabled until all agents stage rewrite
- Clash UA sniff widened (verge/koala/party/…); `profile-update-interval: 1`
