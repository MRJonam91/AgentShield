# Changelog — AgentShield

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file. /
All notable changes to this project are documented in this file.

Il formato è basato su [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
e rispetta il [Semantic Versioning](https://semver.org/).

## [0.2.0-alpha.1] - 2026-11-06

### Added / Aggiunto
- **MCP Tool List Filtering**: intercettazione automatica di `tools/list` su server MCP: gli strumenti con policy `deny` vengono esclusi dall'elenco visibile all'agente per neutralizzare la ricognizione tramite prompt injection; gli strumenti con policy `ask` vengono arricchiti con annotazione descrittiva `[AgentShield: Requires Human Approval]`.
- **HMAC Cryptographic Audit Signatures**: supporto opzionale a segreto HMAC-SHA256 (`auditSecret` o variabile d'ambiente `AGENTSHIELD_SECRET`) per la firma inviolabile dei record di audit e non-ripudiabilità.
- **Audit Search & Filter**: nuovo comando CLI `agentshield audit search` e metodo `AuditTrail.query()` per filtrare eventi di audit per `agentId`, `tool`, `decision` e paginazione.
- **Numeric Bounds Constraints**: supporto a vincoli numerici `numericBounds` (`min`, `max`) su argomenti (es. limiti di importo su transazioni, limiti di righe).
- **Nested Dot-Notation Property Resolution**: supporto per percorsi annidati (es. `options.force`, `target.branch`) sia per pattern regex che per uguaglianze esatte `argumentMatches`.
- **Context-Aware Policies**: matching delle regole condizionato al contesto d'esecuzione (`contextConditions`, es. `userRole`, `environment`).
- **Human Confirmation Timeout**: timeout configurabile (`askTimeoutSeconds`, default 30s) con fallback automatico e sicuro su rifiuto (`ASK_REJECTED`) in caso di mancata risposta operatore.
- **ANSI Terminal Styling & Environment Overrides**: output CLI a colori privo di dipendenze con supporto per `AGENTSHIELD_POLICY`, `AGENTSHIELD_AUDIT_LOG`, `AGENTSHIELD_SECRET`.
- **Suite di Test Estesa**: 22 test automatizzati coprenti tutte le funzionalità Alpha e le protezioni di sicurezza.

## [0.1.0] - 2026-11-06

### Added / Aggiunto
- **Policy Engine**: motore deterministico di regole di sicurezza per chiamate tool degli agenti AI con azioni `allow`, `deny`, `ask` (human-in-the-loop) e `redact`.
- **Constraint Validators**: convalida automatica contro path traversal (`allowedPaths`, `forbiddenPaths`), comandi consentiti/vietati (`allowedCommands`, `forbiddenCommands`), e pattern di argomenti.
- **Rate & Threshold Limiter**: limiti di frequenza e budget per strumento e sessione agente.
- **Tamper-Evident Audit Trail**: log crittografico con concatenazione SHA-256 (`prevHash`), verifica dell'integrità del registro e rilevamento immediato di manomissioni o alterazioni.
- **MCP Stdio Interceptor**: adapter trasparente per strumenti Model Context Protocol (MCP) via stdio JSON-RPC.
- **Programmatic Wrapper**: funzione `wrapTool` per proteggere funzioni asincrone in qualsiasi runtime Node/TS.
- **CLI Suite**: comandi `agentshield eval`, `agentshield exec`, `agentshield mcp`, `agentshield audit verify`, `agentshield audit tail`, `agentshield init`.
- **Bilingual Documentation**: README in italiano e inglese, architettura, threat model, checklist di lancio e suite di test completa.
