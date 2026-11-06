# AgentShield: decision seed / punto di partenza

IT — Scopo: Agenti diversi accedono a tool e dati con permessi poco chiari. Prima prova: Policy locale su un solo adapter di tool, con deny, ask e audit verificabili.

EN — Purpose: Different agents access tools and data with unclear permissions. First trial: Local policy for one tool adapter with verifiable deny, ask and audit.

## Traguardi e Versioni / Milestones & Releases

- **MVP (v0.1.0)**: Motore di policy deterministico (`allow`, `deny`, `ask`, `redact`), adapter MCP stdio JSON-RPC 2.0 e audit trail crittografico con concatenazione SHA-256 (`prevHash`).
- **Versione Alfa (v0.2.0-alpha.1)**:
  - Filtraggio attivo di `tools/list` su MCP per prevenire probe e ricognizione.
  - Firma HMAC crittografica per audit trail con chiave segreta (`auditSecret`).
  - Vincoli su proprietà annidate (dot-notation), limiti numerici (`numericBounds`) e condizioni di contesto (`contextConditions`).
  - Timeout automatico per conferme umane (default 30s) con fallback sicuro su rifiuto.
- **Versione Beta (v0.3.0-beta.1)**:
  - Protezione SSRF per strumenti di rete con blocco IP privati, cloud metadata e whitelist domini.
  - Analisi SQL euristica per database read-only.
  - Tracciamento quote di sessione e budget cumulativi (`sessionQuota`).
  - Ereditarietà policy (`extends`) e validazione strutturale (`agentshield validate`).
  - Statistiche ed esportazione forense audit in JSON, CSV e Markdown (`audit stats`, `audit export`).
- **Versione 1.0 Stabile (v1.0.0)**:
  - Consolidamento architetturale, documentazione completa, test suite a 29 test automatizzati e pubblicazione pubblica.
  - Standard di qualità rispettati: core < 1.500 righe (1.253 righe), licenza Apache-2.0, conformità DCO, CI multi-versione Node.js.
