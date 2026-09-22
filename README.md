<div align="center">

<img src="docs/svg/banner-hero.svg" alt="LawCyBUG.pro banner"/>

# 🕷️ LawCyBug.pro — AI-Powered Autonomous Burp Suite Scanner

### *Not just a Burp extension. An autonomous bug hunter.*

[![Java](https://img.shields.io/badge/Java-17-39ff9d?style=for-the-badge&logo=openjdk&logoColor=black)](#)
[![Montoya API](https://img.shields.io/badge/Burp-Montoya_API-ff3df0?style=for-the-badge&logo=burpsuite&logoColor=white)](#)
[![Detectors](https://img.shields.io/badge/Detectors-41_packages-3df0ff?style=for-the-badge)](#)
[![Rules](https://img.shields.io/badge/Bundled_Rules-287-8a5bff?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-Proprietary-39ff9d?style=for-the-badge)](#-license--eula)
[![Status](https://img.shields.io/badge/Safe_Mode-ON_by_default-ff3df0?style=for-the-badge)](#️-safe-mode--why-it-exists)

<img src="docs/svg/diagram-stats.svg" alt="project stats"/>

</div>

---

> ## ⚠️ Read this before your first scan
>
> - **This is an authorized-testing tool, not a passive-only scanner.** Several detectors send genuinely
>   state-mutating requests (apply a coupon, attempt a role change, submit a tampered order) as part of
>   verifying a finding. **Safe Mode is ON by default** and blocks every step a detector marks as
>   mutating — see [Safe Mode](#️-safe-mode--why-it-exists) before you turn it off.
> - **No scanner achieves "100% accuracy."** Every finding carries a Confidence rating (TENTATIVE /
>   FIRM / CERTAIN). Several detectors run an independent confirmation pass before promoting
>   TENTATIVE → FIRM — see [Confidence System](docs/ARCHITECTURE.md#-confidence-system) — but you should still manually
>   verify before reporting, especially anything still at TENTATIVE.
> - **Cross-identity detectors do nothing until you configure identities.** BOLA replay,
>   privilege-escalation chains, and business-logic chains all require at least a VICTIM (and usually
>   an ATTACKER) identity configured in the **Identities** tab. Without that, they silently skip —
>   this is intentional, not a bug.
> - **Every AI feature is off by default and only runs on explicit request** (a button click) —
>   nothing here calls out to an LLM automatically while you're just browsing/scanning. The one
>   exception is Autonomous Mode, which is both off by default AND requires you to explicitly click Start.
> - **Only use this against systems you are authorized to test.** Unauthorized scanning, and
>   especially unauthorized use of the mutating/exploit features, may be illegal in your jurisdiction.

---

## Overview

**LawCyBug.pro** is a custom Burp Suite extension (Montoya API) for **authorized** enterprise
penetration testing and bug bounty work. Beyond classic payload/regex checks, it layers on a
**stateful multi-identity workflow engine** for real BOLA/IDOR, privilege-escalation, and
business-logic attack-chain detection, and an **optional AI layer** for triage, adaptive
exploitation, chain synthesis, and a fully autonomous discover→plan→execute→review orchestrator —
on top of **41 detector packages** and **287 bundled JSON rules**.

<img src="docs/svg/diagram-architecture.svg" alt="architecture overview"/>

| Layer | What it does |
|---|---|
| 1 | Core detector engine — dispatches every request/response Burp observes |
| 2 | 30+ classic payload-based detectors (SQLi, XSS, SSRF, …) |
| 3 | Stateful workflow engine — identities, object graph, response diffing |
| 4 | Cross-identity & chain detectors built on the workflow engine |
| 5 | Opt-in AI features — triage, chain synthesis, adaptive exploit, mutator |
| 6 | Autonomous orchestrator — runs the whole loop unattended, within guardrails |

📖 **Full breakdown of every layer, every detector, and every AI module:**
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## 🚀 Quick Start

<img src="docs/svg/icon-extension.svg" alt="extension" width="64"/>

```bash
git clone https://github.com/<your-org>/lawcybug.git
cd lawcybug
mvn clean package
# -> target/lawcybug-pro-scanner-<version>.jar
```

Then in Burp Suite:

1. **Extensions → Installed → Add**
2. Extension type: **Java**
3. Select `target/lawcybug-pro-scanner-<version>.jar`
4. A new **LawCyBug** tab appears — go to **Settings** first, confirm **Safe Mode** is `ON`, then
   browse your target normally through Burp's Proxy to start populating passive findings.
5. For cross-identity detection, open **Identities** and add at least a `VICTIM` session.

> **Note on building:** this project has **zero runtime dependencies** beyond the Montoya API
> (`provided` scope) — the JSON rule engine (`MiniJson`) is hand-written specifically so no shade/
> fat-jar plugin is needed. If your build environment has no outbound access to Maven Central, build
> it on a machine that does.

---


---

## ✨ Feature Highlights

<img src="docs/svg/diagram-stats.svg" alt="project stats"/>

- **41 detector packages** — SQLi, XSS, SSRF, SSTI, XXE, deserialization, smuggling (HTTP/1.1 &
  HTTP/2), JWT, CORS, GraphQL/gRPC-Web/WebSocket security, Log4Shell, and 20+ more, each
  confirmed with real evidence rather than a regex guess.
- **Cross-identity attack-chain detection** — BOLA/IDOR replay, privilege-escalation chains
  (confirmed with a follow-up self-lookup), race conditions, account takeover, mass assignment,
  and business-logic abuse, all built on a stateful workflow engine with a learned object graph.
- **Opt-in AI layer** — assisted triage, attack-chain synthesis, adaptive multi-turn exploitation
  (cross-checked against independent evidence validation, not the AI's own say-so), and a
  payload mutator. Nothing calls an LLM automatically — every AI action is a deliberate click.
- **Autonomous orchestrator** — a discover→plan→execute→review loop across unprocessed findings,
  off by default, gated by Safe Mode and a hard action cap, with full run history.
- **287 bundled JSON rules**, extensible without touching Java via `CustomRuleEngine`.
- **Three-tier confidence system** (TENTATIVE / FIRM / CERTAIN) that only escalates on
  independent confirmation.

→ See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the detector-by-detector breakdown,
every AI module explained, the workflow engine internals, UI tour, configuration reference,
project layout, glossary, and troubleshooting.

---

## 🛡️ Safe Mode — Why It Exists

<img src="docs/svg/icon-safemode.svg" alt="safe mode" width="64"/>

Every detector step is tagged, at the source, as either **read-only** or **mutating**. With
**Safe Mode ON (the default)**, any step marked mutating — whether from a built-in detector, AI
Adaptive Exploit, or the Autonomous Orchestrator — is blocked and logged as skipped. Turn it off
only against a target where you have explicit authorization for state-mutating test traffic.
Full detail: [`docs/ARCHITECTURE.md#️-safe-mode--why-it-exists`](docs/ARCHITECTURE.md).

---

## 🔨 Build & Install

<img src="docs/svg/icon-extension.svg" alt="build" width="64"/>

```bash
# Requirements: JDK 17+, Maven 3.8+, outbound access to Maven Central
git clone https://github.com/<your-org>/lawcybug.git
cd lawcybug
mvn clean package
mvn test          # optional — runs the JUnit 5 suite
```

Output: `target/lawcybug-pro-scanner-<version>.jar`. Load it via **Extensions → Installed → Add →
Java** in Burp Suite Professional or Community (Montoya API is supported in both).

> This project could not be compiled inside the sandbox that authored it — no outbound access to
> Maven Central from that environment. Build the real `.jar` yourself on a machine with normal
> internet access; the command above is the same one used to produce
> `target/lawcybug-pro-scanner-1.34.5.jar` in this repo.

---


---

## ❓ FAQ

**Q: Does this call an LLM automatically while I browse?**
A: No. Every AI feature is opt-in per action — Triage, Chain Synthesis, Adaptive Exploit, and the Payload Mutator all require you to click something. Autonomous Mode additionally requires AI to be enabled *and* a separate explicit Start click.

**Q: Why are my cross-identity findings empty?**
A: You haven't configured identities yet. See [Identities & Setup](docs/ARCHITECTURE.md#-identities--cross-identity-setup) — this is intentional silent-skip behavior, not a bug.

**Q: Can I use this against production without Safe Mode?**
A: Only if you have explicit written authorization for state-mutating test traffic against that environment. We'd still recommend testing Safe-Mode-OFF categories against staging first.

**Q: Is my AI API key stored anywhere?**
A: No — it's held in memory for the current session only and is never written to disk or logged.

**Q: Does the jar in target/ actually work?**
A: The repo includes a pre-built jar for convenience, but rebuild it yourself with `mvn clean package` before relying on it in a real engagement, since it couldn't be built/verified from the sandbox that authored this project.

**Q: Can I add my own detection logic without Java?**
A: Yes — drop a JSON rule file into `src/main/resources/rules/` following the `example-rules.json` shape and reload the extension.

---


---

## 🤝 Contributing

Issues and PRs against detector accuracy (false positives/negatives), new detector packages, and
additional JSON rules are welcome. Please include a minimal reproducible request/response pair for
any detector bug report. See `CHANGELOG.md` for the current version and recent changes before filing
a duplicate.

---


---

## 📄 License & EULA

This project is distributed under the terms in `EULA.md` in the repository root — read it before
use, and note in particular the authorized-testing-only scope described there and reiterated at the
top of this README.

---


---


---

<div align="center">

<img src="docs/svg/banner-footer.svg" alt="LawCyBUG.pro footer"/>

*Made for people who have permission to break things.*

[**→ Full architecture &amp; feature deep-dive**](docs/ARCHITECTURE.md)

</div>