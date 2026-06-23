# BOLT 12 test vectors

Vendored from `lightning/bolts` repo (commit-pinned at vendor time):
<https://github.com/lightning/bolts/tree/master/bolt12>

- `format-string-test.json` — bech32-no-checksum string handling
  (case rules, `+` continuation, surrounding whitespace).
- `signature-test.json` — `LnLeaf` / `LnNonce` / `LnBranch` merkle
  construction + per-message signature digest.
- `offers-test.json` — full `lno...` round-trip cases.
- `SPEC.md` — `12-offer-encoding.md` from the spec at vendor time, kept
  alongside the vectors so reviewers can resolve any future spec drift.

These vectors are the authoritative correctness gate for
`app/services/bolt12/` — see `tests/unit/test_bolt12_codec.py`.

When updating, re-vendor all four files together so the spec text and
vectors stay in sync.
