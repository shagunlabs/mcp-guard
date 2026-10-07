# Sentryra Evidence v0 (draft, Apache-2.0)
- Entry: canonical JSON (RFC 8785 JCS target; M0 code uses sorted-key JSON) with `seq`, `decision_id`, `tool`, `resource`, `args_hmac`, `decision`, `prev_hash`, … (full list: tech spec §11).
- `entry_hash = SHA-256(canonical(entry without entry_hash) || prev_hash)`; genesis `prev_hash` = 64 zeros.
- Arguments are stored only as `HMAC(tenant_evidence_key, canonical_args)`; the key never leaves the data plane.
- Per-entry Ed25519 instance signatures, Merkle tiles and C2SP signed checkpoints: M3. A bare chain does **not** detect tail truncation; checkpoints do.
