## v2.3.2 — Core inbound: full settings + auto TLS via nginx

- Creating/editing an inbound from a core opens the full inbound form (nginx/direct, share host, WS, Reality, uTLS, …)
- When «Напрямую на порт» is unchecked (path via nginx), client config links automatically get `security=tls` on `:443`
- External Proxies with `forceTls=same` also keep TLS for nginx Path inbounds
- Badge `nginx→tls` in the core inbound list
