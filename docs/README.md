# Documentation Index

User- and operator-facing guides for Agent Wallet. Each file covers what an end
user or operator needs to know to configure and run a feature — background,
configuration, and runbook material. Start with the [project README](../README.md)
for an overview, and see the [DISCLAIMER](../DISCLAIMER.md) before use.

| Document | What it covers |
|---|---|
| [anonymize.md](anonymize.md) | Forward-anonymity ("Anonymize") sessions: pipeline, score tiers, quick start, and operator runbook |
| [anonymize_operator_diversity.md](anonymize_operator_diversity.md) | Operator-diversity threat model, score-tier definitions, and registry vetting rationale |
| [anonymize_troubleshooting.md](anonymize_troubleshooting.md) | Per-reason recovery steps for Anonymize sessions stuck in `awaiting_reconciliation` |
| [api-keys.md](api-keys.md) | API-key lifecycle management (create, rename, rotate, scope, revoke, purge) via the dashboard and REST |
| [bolt12.md](bolt12.md) | BOLT 12 protocol notes, the Rust onion-message gateway, optional mTLS, and threat model |
| [boltz.md](boltz.md) | Boltz Exchange swap integration used for cold-storage sweeps and Anonymize hops |
| [boltz_recovery.md](boltz_recovery.md) | Recovering stuck or pending Boltz swaps |
| [braiins_deposit.md](braiins_deposit.md) | Guided round-amount deposit flow for Braiins Hashpower and similar services |
| [electrs.md](electrs.md) | Opting in to a self-hosted electrs chain backend in place of the Mempool Explorer HTTP backend |
| [lnurl.md](lnurl.md) | LNURL-pay and Lightning Address send flow (dashboard-only) |
| [operator_tor_runbook.md](operator_tor_runbook.md) | Operating the bundled Tor SOCKS5 proxy: monitoring, data-directory growth, and troubleshooting |
| [secret_key_backup.md](secret_key_backup.md) | Backing up and protecting `SECRET_KEY` and related at-rest encryption material |
