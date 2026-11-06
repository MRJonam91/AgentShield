# Contribuire / Contributing — AgentShield

## 🇮🇹 Italiano

Grazie! Il progetto è pensato per essere capito e verificato rapidamente: il **core** (`src/core/`) resta sotto le
**1.500 righe** e gli adapter o le integrazioni vivono in `src/adapters/` o `examples/`.

1. Apri una issue per discutere modifiche architetturali o nuovi adapter.
2. `npm run typecheck && npm test` devono passare (Node ≥ 22.18, zero dipendenze esterne di runtime).
3. Un test deterministico per ogni regola, controllo di policy o fix di sicurezza.
4. Header SPDX (`// SPDX-License-Identifier: Apache-2.0`) in ogni nuovo file sorgente.
5. Messaggi di commit in stile [Conventional Commits](https://www.conventionalcommits.org/it/).
6. Firma ogni commit con il DCO: `git commit -s`.

Vedi [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) per i dettagli sul motore di policy e sul log verificabile.

## 🇬🇧 English

Thanks! The project is designed to be easily audited and extended: the **core** (`src/core/`) stays strictly under
**1,500 lines** and adapters or integrations live in `src/adapters/` or `examples/`.

1. Open an issue to discuss architectural changes or new adapters.
2. `npm run typecheck && npm test` must pass (Node ≥ 22.18, zero external runtime dependencies).
3. One deterministic test for every policy check, rule match, or security fix.
4. SPDX header (`// SPDX-License-Identifier: Apache-2.0`) in every new source file.
5. Commit messages following [Conventional Commits](https://www.conventionalcommits.org/).
6. Sign off every commit with the DCO: `git commit -s`.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details on the policy engine and verifiable audit trail.
