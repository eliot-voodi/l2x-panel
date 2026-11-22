## v2.2.5 — Reality SNI conflict fix (second inbound was unreachable)

- Two Reality inbounds with the same camouflage SNI (e.g. both `www.cloudflare.com`) could not both publish on nginx `:443` — the second looked fine in JSON but was dead on the client
- On Apply / inbound save: auto-assign the next free Reality camouflage SNI and set Vision flow when empty
- Amsterdam-1 on live: SNI → `www.microsoft.com`, flow → `xtls-rprx-vision`, nginx map has both ports
