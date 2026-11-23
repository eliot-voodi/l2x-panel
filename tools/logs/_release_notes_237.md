## v2.3.7 — Mihomo Reality: ML-KEM key share

- Clash/Mihomo Reality nodes now export `reality-opts.support-x25519mlkem768: true`
- Reality client fingerprint forced to `chrome` when inbound had `firefox`/`edge`/… (those uTLS profiles lack ML-KEM → `REALITY Authentication: false` on Xray ≥26.9.8)
- Raw `vless://` Reality links also carry `support-x25519mlkem768=true` + `fp=chrome`
