# L2X Tunnel (Go)

UDP L4 tunnel agent/portal per [docs/TZ_TUNNEL_AGENT.md](../docs/TZ_TUNNEL_AGENT.md).

## Binaries

- `l2x-tunneld` — portal on master (UDP + local TCP proxy)
- `l2x-tunnel-agent` — NAT node agent (egress dials)
- `l2x-dnsd` — MasterDNS DNS-tunnel server (UDP/TCP :53, health `:9111`)

## Quick lab (same host)

```bash
cd tunnel
./deploy/install.sh
# set matching psk/token in /etc/l2x-tunnel/*.yaml
systemctl restart l2x-tunneld l2x-tunnel-agent
curl -s http://127.0.0.1:9109/health
curl -s http://127.0.0.1:9110/health
curl -v --proxy http://127.0.0.1:18080 http://1.1.1.1/  # needs HTTP proxy — use nc/tcp test instead:
printf 'GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n' | nc -q2 127.0.0.1 18080
```

TCP proxy on portal opens a stream; agent dials `default_dial` (e.g. `1.1.1.1:80`).
