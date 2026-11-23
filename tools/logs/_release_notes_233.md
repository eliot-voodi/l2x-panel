## v2.3.3 — Mihomo/Clash: VLESS encryption (ML-KEM)

- Clash/Mihomo subscription now exports VLESS `encryption` (e.g. `mlkem768x25519plus…`) — previously missing, so gRPC/WS PQ nodes failed or were dropped
- `packet-encoding: xudp` for VLESS/VMess UDP
- gRPC: optional `grpc-authority` from transport Host
- Same `encryption` field for sing-box export
