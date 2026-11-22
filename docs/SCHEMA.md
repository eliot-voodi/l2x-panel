# L2X data model (target PostgreSQL)

Runtime storage today remains a JSON document store (`store.json`) plus `admins.json` and `settings_versions/`.

The **normalized target schema** for a future PostgreSQL migration is in [`schema.dbml`](schema.dbml) (open in [dbdiagram.io](https://dbdiagram.io)).

## Design notes

- Surrogate UUID PKs; `clients.email` stays a unique business key.
- **Core slices are owned snapshots** (`core_inbounds`, `core_outbounds`, …), not FKs to master rows — otherwise `inherit_master=false` configs would be lost.
- Secrets (`password`, WG private, agent tokens, TOTP) are modeled as `*_enc` / `*_hash` columns.
- Traffic counters use `bigint` bytes (not float GB).
- Nothing from the current store is dropped: settings sections, geo_custom, api_tokens, outbound probe history, `_events`, sysmon history, etc. are all represented.
