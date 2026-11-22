## v2.2.6 — Fix WS Path `/` (Amsterdam-1 unreachable behind nginx)

- Path transports with `/?=…` collapsed to `/`, which is reserved for the panel — nginx never published the inbound
- On shape/Apply: auto-rewrite reserved paths to `/<tag>` (e.g. `/amsterdam-1`) and clear Vision flow on non-Reality transports
- Live Amsterdam-1: path `/amsterdam-1`, published on `am.ro0t.dev`, cascade JSON intact
