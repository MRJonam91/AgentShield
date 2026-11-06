# Changelog — AgentShield

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file. /
All notable changes to this project are documented in this file.

Il formato è basato su [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
e rispetta il [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-11-06

### Security & Robustness Hardening / Miglioramenti di Sicurezza e Robustezza
- **Windows Security & ADS Protection**: blocco di NTFS Alternate Data Streams (`test.txt:stream`, `test.txt::$DATA`) e dei nomi di periferiche DOS riservati (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) in `isPathSafe`.
- **SSRF Hardening**: potenziamento del rilevatore SSRF contro notazioni IPv6-mapped IPv4 private e loopback (`[::ffff:127.0.0.1]`, `[fe80:]`, `[fc]`, `[fd]`) in `isUrlSafe`.
- **Rule Specificity Scoring**: precedenza deterministica basata su punteggio di specificità delle regole (`matchRule`), garantendo che regole specifiche per singolo tool abbiano sempre priorità rispetto alle regole generiche wildcard (`*`).
- **Deep Structural Argument Matching**: confronto profondo e strutturale di oggetti e array annidati in `argumentMatches` con ordinamento canonico delle chiavi.
- **Circular Reference Protection**: sanificazione ricorsiva protetta con `WeakSet` in `redactSecrets`, prevenendo blocchi o stack overflow su grafi di oggetti ciclici.
- **MCP Error Handling & JSON-RPC 2.0 Compliance**: gestione corretta delle notifiche JSON-RPC 2.0 (nessuna risposta inviata se il messaggio è privo di `id`) e gestione errori sull'evento `error` del processo figlio MCP spawnato.
- **CLI Shell Tolerance**: helper `parseLooseJson` per gestire argomenti JSON con apici rimossi o formati rilassati tipici di alcune shell (es. PowerShell).
- **Test Suite Expansion**: 34 test automatizzati (5 nuovi test per edge cases e vulnerabilità specifiche), con tempo di esecuzione < 500ms.

## [1.0.0] - 2026-11-06

### Stable Release / Versione Stabile
- **General Availability (GA)**: rilascio ufficiale stabile v1.0 di AgentShield come runtime firewall e middleware di sicurezza deterministico per agenti AI e tool MCP.
- **Zero Runtime Dependencies**: architettura leggera e veloce basata esclusivamente sulle API native di Node.js (Node >= 22.18).
- **Core Size Compliance**: codice core mantenuto rigorosamente sotto le 1.500 righe non vuote (1.253 LOC).
- **Comprehensive Test Suite**: 29 test automatizzati coprenti motore di policy, audit crittografico, prevenzione SSRF, protezione database SQL, rate limiter e quote di sessione.
- **Open Standards Compliance**: conformità DCO, licenza Apache-2.0, e canali di sponsorizzazione e donazione configurati.

## [0.3.0-beta.1] - 2026-11-06

### Added / Aggiunto
- **SSRF Network Protection**: protezione contro Server-Side Request Forgery su strumenti di rete (`fetch`, `http_request`, `webhook`), blocco automatico di loopback (`localhost`, `127.0.0.1`), metadata cloud (`169.254.169.254`, `metadata.google.internal`), reti private (RFC 1918) e whitelist domini (`allowedDomains`).
- **SQL Safety Analyzer**: analisi euristica per database read-only (`readOnlySql`), con blocco di operazioni distruttive (`DROP`, `DELETE`, `UPDATE`, `INSERT`, `TRUNCATE`, `ALTER`) ed evasioni tramite commenti.
- **Session Quotas & Cumulative Budgets**: tracciamento del budget cumulativo e quote per sessione agente (`sessionQuota`), con controllo sul numero massimo di chiamate e sui valori cumulativi monetari o contabili (es. budget massimo di spesa per sessione).
- **Policy Inheritance (`extends`) & Validation**: supporto all'ereditarietà delle policy tramite `extends: "./base.json"` e comando di validazione strutturale `agentshield validate`.
- **Forensic Audit Stats & Export**: nuovo comando `agentshield audit stats` per sintesi statistica forense delle decisioni e `agentshield audit export` con esportazione in JSON, CSV e Markdown per audit e conformità.
- **Suite di Test Estesa**: 29 test automatizzati con copertura completa di tutte le difese di sicurezza Beta.

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
