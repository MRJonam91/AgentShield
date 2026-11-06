# Architettura / Architecture — AgentShield

```
                                  ┌───────────────────────────────┐
                                  │   AI Agent / LLM Runtime      │
                                  │ (Claude, LangChain, MCP host) │
                                  └──────────────┬────────────────┘
                                                 │ Tool Call Request
                                                 ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                             AgentShield Core Engine                            │
│                                                                                │
│  1. Match Rule (agentId, tool pattern glob)                                    │
│  2. Sanitize & Redact (API keys, Bearer tokens, private keys)                  │
│  3. Evaluate Constraints (allowedPaths, forbiddenPaths, rateLimit, regex)      │
│  4. Resolve Action:                                                            │
│     ├── ALLOW ────────► Execute Tool Adapter                                   │
│     ├── DENY ─────────► Block immediately + Security Violation                 │
│     ├── ASK ──────────► Request Human-in-the-Loop Confirmation                 │
│     └── REDACT ───────► Sanitize payload + Permit                              │
│                                                                                │
│  5. Tamper-Evident Audit Record:                                               │
│     hash = SHA256(index | timestamp | id | agent | tool | args | verdict | prev)│
└───────────────────────┬──────────────────────────────────┬─────────────────────┘
                        │                                  │
                        ▼ Allowed / Sanitized              ▼ Immutable Log
       ┌─────────────────────────────────┐        ┌──────────────────┐
       │ Tool Adapter (MCP, CLI, SDK fn) │        │ Audit Chain      │
       └─────────────────────────────────┘        │ (.jsonl)         │
                                                  └──────────────────┘
```

## 🇮🇹 Concetti del Core

1. **Policy Engine (`src/core/engine.ts`)**:
   - Valutazione deterministica `allow`, `deny`, `ask`, `redact`.
   - Matching a pattern (es. `*`, `fs:*`, `agent-*`).
   - Vincoli di sicurezza:
     - `allowedPaths`: contenimento directory, blocco traversamento (`../`, null byte, URI encode).
     - `forbiddenPaths`: blocco percorsi sensibili (`.env`, `.git/config`, `id_rsa`, `/etc/passwd`).
     - `allowedCommands` / `forbiddenCommands`: espressioni regolari per shell command injection.
     - `rateLimit`: finestre temporali scorrevoli contro burst e loop infiniti.
2. **Cryptographic Audit Trail (`src/core/audit.ts`)**:
   - Concatenazione crittografica hash SHA-256 (`prevHash`).
   - Serializzazione JSON canonica ordinata.
   - Verifica di integrità immediata tramite `agentshield audit verify` che rileva alterazioni, cancellazioni o scambi di riga.
3. **Sanitizer (`src/core/sanitizer.ts`)**:
   - Riconoscimento automatico e mascheramento di segreti e chiavi API (OpenAI, Anthropic, GitHub, JWT, chiavi RSA/ED25519).

### Estendere
- **Nuovo adapter**: vedi `src/adapters/mcp.ts` per implementare proxy o wrapper di trasporto (es. HTTP, WebSocket, gRPC).
- **Nuove regole di policy**: JSON dichiarativo in `agentshield.json`.

---

## 🇬🇧 Core Concepts

1. **Policy Engine (`src/core/engine.ts`)**:
   - Deterministic rule resolution (`allow`, `deny`, `ask`, `redact`).
   - Wildcard glob pattern matching (e.g. `*`, `fs:*`, `agent-*`).
   - Security constraints:
     - `allowedPaths`: workspace confinement, blocks traversal (`../`, null bytes, URI encoding).
     - `forbiddenPaths`: blocks sensitive targets (`.env`, `.git/config`, `id_rsa`, `/etc/passwd`).
     - `allowedCommands` / `forbiddenCommands`: regex checking against shell injections.
     - `rateLimit`: sliding window counter preventing runaway agent loops.
2. **Cryptographic Audit Trail (`src/core/audit.ts`)**:
   - SHA-256 hash chaining (`prevHash`).
   - Deterministic canonical JSON key sorting.
   - Instant tamper detection via `agentshield audit verify`.
3. **Sanitizer (`src/core/sanitizer.ts`)**:
   - Automatic detection and redaction of secrets, tokens, private keys.

### Extending
- **New adapters**: See `src/adapters/mcp.ts` to implement custom transport proxies (HTTP, WebSocket, gRPC).
- **New policy rules**: Declarative JSON in `agentshield.json`.
