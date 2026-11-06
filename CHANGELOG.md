# Changelog — AgentShield

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file. /
All notable changes to this project are documented in this file.

Il formato è basato su [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
e rispetta il [Semantic Versioning](https://semver.org/).

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
