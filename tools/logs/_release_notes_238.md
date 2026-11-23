## v2.3.8 — Fix Amsterdam WS in subscription

- Stop emitting per-user cosmetic `/u-…` WS paths until all agents stage the nginx rewrite (old agents → 404 / delay fail; real `/ws` works)
- Keeps v2.3.7 Reality fix: `support-x25519mlkem768: true` + chrome fingerprint for Mihomo
