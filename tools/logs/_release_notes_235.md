## v2.3.5 — Sanitize WS paths for Mihomo

- Strip broken WS path queries like `?=junk` (keep only valid `ed=N` early-data)
- Clash/Mihomo and share links use the cleaned path
