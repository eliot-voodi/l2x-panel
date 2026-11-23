## v2.3.4 — Mihomo: keep ML-KEM gRPC nodes

- Clash YAML: drop non-standard `grpc-authority` (some Meta builds skipped the whole proxy)
- Safer dump of long VLESS `encryption` strings
- Format sniffing: do not force Xray JSON onto curl/go-http converters when `json_default` is on — use Clash for Mihomo/Clash Meta UAs
- Tip: force Clash with `?format=clash` on the subscription URL
