# AgentShield: decision seed / punto di partenza

IT — Scopo: Agenti diversi accedono a tool e dati con permessi poco chiari. Prima prova: Policy locale su un solo adapter di tool, con deny, ask e audit verificabili.

EN — Purpose: Different agents access tools and data with unclear permissions. First trial: Local policy for one tool adapter with verifiable deny, ask and audit.

## Decisioni prese / Decisions made

- **Prima prova verificabile completata (v0.1.0)**: Motore di policy deterministico (`allow`, `deny`, `ask`, `redact`), adapter MCP stdio JSON-RPC 2.0 e audit trail crittografico con concatenazione SHA-256 (`prevHash`).
- **Avanzamento a Versione Alfa (v0.2.0-alpha.1)**:
  - Filtraggio attivo di `tools/list` su MCP per prevenire probe e ricognizione.
  - Firma HMAC crittografica per audit trail con chiave segreta (`auditSecret`).
  - Vincoli su proprietà annidate (dot-notation), limiti numerici (`numericBounds`) e condizioni di contesto (`contextConditions`).
  - Timeout automatico per conferme umane (default 30s) con fallback sicuro su rifiuto.
  - Interfaccia CLI arricchita con comando `audit search`, styling ANSI zero-dependency e supporto a variabili d'ambiente.
- **Standard applicati**: `../_repo-kit/REPO-STANDARDS.md` rispettato integralmente (core < 1.500 righe [945 righe], licenza Apache-2.0, NOTICE, LICENSING.md, donazioni, CI, 7/7 marker verificati in `_provenance/AgentShield.json`).
- **Misura di successo osservata**: 22/22 test automatizzati passati con successo.
