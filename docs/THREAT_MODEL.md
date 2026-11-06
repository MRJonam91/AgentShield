# Threat Model — AgentShield

## Threat Vectors & Defenses

| Threat Vector / Vettore | Attack Scenario | AgentShield Mitigation |
|---|---|---|
| **Path Traversal & System File Access** | Agent or prompt injection attempts reading `/etc/passwd`, `C:\Windows`, `~/.ssh/id_rsa`, or `../../.env` | Path normalization, URI decode check, null-byte block, and strict `allowedPaths` root confinement. |
| **Command Injection & Destruction** | Agent attempts executing `rm -rf /`, formatting disks, or downloading arbitrary executables | `allowedCommands` / `forbiddenCommands` regex scanning, fallback to default `deny` or `ask`. |
| **Data & Secret Exfiltration** | Agent dumps API keys or passwords into external query or tool arguments | `redactSecrets` scrubs OpenAI, Anthropic, GitHub keys, Bearer tokens, private keys. |
| **Runaway Bursts / Denial of Wallet** | Agent gets stuck in loop invoking billable APIs thousands of times | In-memory sliding window `rateLimit` (max calls per time interval). |
| **Silent Actions / Audit Log Alteration** | Malicious agent or insider attempts deleting or tampering with security logs to hide actions | SHA-256 cryptographic chaining (`prevHash`). Any modification breaks `agentshield audit verify`. |
| **High-Impact Critical Actions** | Agent attempts database deletion or funds transfer without human oversight | `ask` action requiring explicit interactive Human-in-the-Loop operator approval (`ASK_APPROVED` / `ASK_REJECTED`). |

## Boundaries & Non-Goals

- AgentShield is not a hypervisor or kernel sandbox. System processes spawned by tools run under the user's OS permissions.
- Where operating system isolation is required, AgentShield is designed to be paired with `WASM-Sandbox` or Docker containers.
