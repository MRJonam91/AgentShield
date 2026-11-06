# AgentShield: decision seed / punto di partenza

IT — Scopo: Agenti diversi accedono a tool e dati con permessi poco chiari. Prima prova: Policy locale su un solo adapter di tool, con deny, ask e audit verificabili.

EN — Purpose: Different agents access tools and data with unclear permissions. First trial: Local policy for one tool adapter with verifiable deny, ask and audit.

## Decisioni prese / Decisions made (2026-11-06)

- **Prima prova verificabile completata**: Motore di policy deterministico (`allow`, `deny`, `ask`, `redact`), adapter MCP stdio JSON-RPC 2.0 e audit trail crittografico con concatenazione SHA-256 (`prevHash`).
- **Standard applicati**: `../_repo-kit/REPO-STANDARDS.md` rispettato integralmente (core < 1.500 righe [703 righe], licenza Apache-2.0, NOTICE, LICENSING.md, donazioni, CI, 7/7 marker verificati in `_provenance/AgentShield.json`).
- **Misura di successo osservata**: 14/14 test passati (unit test, path traversal prevention, rate limiting, human approval, tamper detection dell'audit log).
