<div align="center">

<img src="svg/banner-hero.svg" alt="LawCyBUG.pro banner"/>

# 🕷️ LawCyBug.pro — Architecture &amp; Feature Deep-Dive

[← back to README](../README.md)

</div>

---

## 📚 Table of Contents

- [Architecture](#-architecture)
- [Layer 1 — Core Detector Engine](#-layer-1--core-detector-engine)
- [Layer 2 — Classic Payload Detectors](#-layer-2--classic-payload-detectors)
- [Layer 3 — Workflow Engine](#-layer-3--workflow-engine)
- [Layer 4 — Cross-Identity & Chain Detectors](#-layer-4--cross-identity--chain-detectors)
- [Layer 5 — AI-Assisted Features](#-layer-5--ai-assisted-features-all-opt-in)
- [Layer 6 — Autonomous Orchestrator](#-layer-6--autonomous-exploit-orchestrator)
- [Custom Rules Engine](#-custom-rules-engine)
- [Confidence System](#-confidence-system)
- [Safe Mode — Why It Exists](#️-safe-mode--why-it-exists)
- [Identities & Setup](#-identities--cross-identity-setup)
- [UI Tour](#-ui-tour)
- [Findings Export](#-findings-export)
- [History, Audit & Suppression](#-history-audit--suppression)
- [Configuration Reference](#-configuration-reference)
- [Project Layout](#-project-layout)
- [Step-by-Step: How a Scan Runs](#-step-by-step-how-a-scan-actually-runs)
- [Detector Package Census](#-detector-package-census)
- [Glossary](#-glossary)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)
- [Version & Acknowledgments](#-version--acknowledgments)

---

## Architecture

Every request Burp's Proxy/Scanner/Repeater sees is handed to the **`DetectorEngine`**, which fans it
out to every registered `ActiveDetector` / `PassiveDetector` implementation. Detectors that need more
than a single request/response pair — the ones behind BOLA, privilege escalation, business logic,
account takeover — are instead built on top of the **`WorkflowEngine`**, which understands identities,
learned object graphs, and can run a guarded multi-step request chain. Everything a detector produces
becomes a `Finding`, normalized through `IssueFactory`, correlated by `FindingsCorrelator`, and
stored in `FindingsStore`. The AI layer and the Autonomous Orchestrator sit *above* all of this — they
read findings and (optionally) drive new requests through the same `WorkflowEngine` and `ChainGuard`
machinery that the built-in detectors use, so the same Safe Mode / budget / throttling rules apply
uniformly whether a request was fired by a hand-written detector or by the AI.

<img src="svg/diagram-request-flow.svg" alt="request lifecycle"/>

**Request lifecycle, step by step:**

- **HTTP Request** — Burp hands the extension a request/response pair from Proxy, live Scanner, or a manual Repeater send (depending on which hooks are enabled in Settings).
- **Passive Scan** — Every `PassiveDetector` inspects the pair with zero extra network traffic — header checks, information disclosure, JWT `alg:none`, passive object-graph learning for `ObjectGraph`.
- **Active Probe** — `ActiveDetector` implementations that are enabled fire *additional*, purpose-built requests — a boolean-blind SQLi pair, an SSTI arithmetic payload, a Collaborator-backed SSRF probe — gated by Safe Mode where the probe mutates state.
- **Evidence Check** — Raw signal (a error string, a timing delta, a Collaborator interaction) is run through category-specific validation in `ExploitEvidenceValidator` / `DifferentialProbeHelper` before it's allowed to become a finding at all.
- **Finding** — A `Finding` is created via `IssueFactory`, given a Confidence rating, checked against `FindingsSuppressionEngine`, correlated against other findings on the same host by `FindingsCorrelator`, and persisted in `FindingsStore` — visible immediately in the LawCyBug tab.

---


---

## 🧩 Layer 1 — Core Detector Engine

<img src="svg/icon-detectorengine.svg" alt="detector engine" width="64"/>
<img src="svg/icon-active.svg" alt="active detector" width="64"/>
<img src="svg/icon-passive.svg" alt="passive detector" width="64"/>

Every detector implements one of two tiny interfaces:

| Interface | When it runs | Network traffic | Examples |
|---|---|---|---|
| `PassiveDetector` | On every request/response Burp already captured | None — inspects only | Security headers, info disclosure, JWT `alg:none` |
| `ActiveDetector` | Opt-in, fires its own probes | Additional requests (Safe-Mode gated if mutating) | SQLi boolean/time-based, SSTI, SSRF Collaborator |

The `DetectorEngine` owns the registry of both, dispatches every observed pair to all *enabled*
detectors, applies global rate-limiting/host-scoping from `RequestFingerprintGuard`, and forwards
anything produced to `IssueFactory`. Two small but important support classes live at this layer:

- **`EndpointClassifier`** — guesses the semantic shape of an endpoint (REST resource, GraphQL,
  gRPC-Web, static asset) so downstream detectors can skip probes that don't make sense for it.
- **`SeverityRecalibrator`** — adjusts a finding's declared severity based on runtime context (e.g.
  auth-required endpoint vs. public, presence of a working PoC) rather than a fixed per-category table.

<img src="svg/diagram-stats.svg" alt="stat bar"/>

---


---

## 🎯 Layer 2 — Classic Payload Detectors

Payload/regex-driven checks, each confirmed with real evidence (not just "looks suspicious") before
being raised. Every card below links to the Java class implementing it.

<table><tr><td><img src="svg/icon-sqli.svg" alt="SQL Injection" width="56"/></td><td>
### SQL Injection
`SqlErrorBasedDetector · SqlBooleanBasedDetector · SqlTimeBasedDetector`

Three independent confirmation strategies: DB error-string fingerprinting, boolean-blind differential response comparison (via `ResponseDiff`), and time-based blind with jitter-tolerant timing analysis (`TimingUtils`).
</td></tr></table>

<table><tr><td><img src="svg/icon-xss.svg" alt="Reflected XSS" width="56"/></td><td>
### Reflected XSS
`ReflectedXssDetector`

Context-aware — determines whether the reflection lands in an HTML body, an attribute, a `<script>` block, or a URL, and only reports when the specific context's breakout actually executes.
</td></tr></table>

<table><tr><td><img src="svg/icon-cmdi.svg" alt="OS Command Injection" width="56"/></td><td>
### OS Command Injection
`BlindCommandInjectionDetector`

Time-based and out-of-band blind command injection, using canary tokens (`CanaryUtils`) to avoid false positives from naturally slow endpoints.
</td></tr></table>

<table><tr><td><img src="svg/icon-ssrf.svg" alt="SSRF" width="56"/></td><td>
### SSRF
`SsrfCollaboratorDetector`

Out-of-band confirmation via Burp Collaborator — a finding is only raised on an actual observed interaction, not a guess based on parameter naming.
</td></tr></table>

<table><tr><td><img src="svg/icon-ssti.svg" alt="Server-Side Template Injection" width="56"/></td><td>
### Server-Side Template Injection
`SstiDetector · SstiCollaboratorDetector`

Arithmetic-confirmed detection (`{{7*7}}`-style) across 10 template engines, plus a separate Collaborator-OOB variant for output that's never reflected back.
</td></tr></table>

<table><tr><td><img src="svg/icon-openredirect.svg" alt="Open Redirect" width="56"/></td><td>
### Open Redirect
`OpenRedirectDetector`

Validates the `Location` header actually points off-host rather than just checking the input parameter shape.
</td></tr></table>

<table><tr><td><img src="svg/icon-cors.svg" alt="CORS Misconfiguration" width="56"/></td><td>
### CORS Misconfiguration
`CorsDetector`

Tests `null` origin, reflected arbitrary origin, and subdomain-wildcard trust, cross-checked against whether credentials are actually allowed.
</td></tr></table>

<table><tr><td><img src="svg/icon-jwt.svg" alt="JWT Misconfiguration" width="56"/></td><td>
### JWT Misconfiguration
`JwtMisconfigDetector`

`alg:none`, weak/guessable HMAC secrets, `kid` header injection, and missing signature verification.
</td></tr></table>

<table><tr><td><img src="svg/icon-xxe.svg" alt="XXE" width="56"/></td><td>
### XXE
`XxeDetectors`

Classic external entity, parameter entity, and OOB-Collaborator variants across common XML-consuming endpoints.
</td></tr></table>

<table><tr><td><img src="svg/icon-deserial.svg" alt="Insecure Deserialization" width="56"/></td><td>
### Insecure Deserialization
`InsecureDeserializationDetector`

Java, PHP, and .NET gadget-chain signature detection plus OOB confirmation where safe.
</td></tr></table>

<table><tr><td><img src="svg/icon-traversal.svg" alt="Path Traversal" width="56"/></td><td>
### Path Traversal
`PathTraversalDetectors`

Multiple encoding variants (raw, URL-encoded, double-encoded, Unicode) against known-sensitive file targets.
</td></tr></table>

<table><tr><td><img src="svg/icon-hostheader.svg" alt="Host Header Injection" width="56"/></td><td>
### Host Header Injection
`HostHeaderInjectionDetector`

Password-reset-poisoning-style Host header tampering, checked for reflection in generated links/emails-adjacent output.
</td></tr></table>

<table><tr><td><img src="svg/icon-crlf.svg" alt="CRLF Injection" width="56"/></td><td>
### CRLF Injection
`CrlfInjectionDetector`

Header/response-splitting via `\r\n` sequences in reflected input.
</td></tr></table>

<table><tr><td><img src="svg/icon-smuggling.svg" alt="HTTP Request Smuggling" width="56"/></td><td>
### HTTP Request Smuggling
`HttpRequestSmugglingDetector`

Classic CL.TE and TE.CL desync detection using differential timing probes.
</td></tr></table>

<table><tr><td><img src="svg/icon-h2smuggling.svg" alt="HTTP/2 Smuggling" width="56"/></td><td>
### HTTP/2 Smuggling
`Http2SmugglingDetector`

H2.TE / H2.CL downgrade-smuggling variants specific to HTTP/2 → HTTP/1.1 backend translation.
</td></tr></table>

<table><tr><td><img src="svg/icon-hpp.svg" alt="HTTP Parameter Pollution" width="56"/></td><td>
### HTTP Parameter Pollution
`HttpParameterPollutionDetector`

Duplicate-parameter handling differences between front-end and back-end parsers.
</td></tr></table>

<table><tr><td><img src="svg/icon-xpath.svg" alt="XPath Injection" width="56"/></td><td>
### XPath Injection
`XPathInjectionDetector`

Boolean-blind XPath injection with dedicated payload sets in `SqlPayloads`-adjacent tables.
</td></tr></table>

<table><tr><td><img src="svg/icon-nosql.svg" alt="NoSQL Injection" width="56"/></td><td>
### NoSQL Injection
`NoSqlInjectionDetector`

MongoDB-style operator injection (`$ne`, `$gt`, `$where`) with boolean-blind confirmation.
</td></tr></table>

<table><tr><td><img src="svg/icon-ldap.svg" alt="LDAP Injection" width="56"/></td><td>
### LDAP Injection
`LdapDetectors`

Filter-injection payloads targeting authentication and search filters.
</td></tr></table>

<table><tr><td><img src="svg/icon-protopollution.svg" alt="Prototype Pollution" width="56"/></td><td>
### Prototype Pollution
`PrototypePollutionDetector`

`__proto__` / `constructor.prototype` payloads with response-side pollution confirmation.
</td></tr></table>

<table><tr><td><img src="svg/icon-cachepoisoning.svg" alt="Web Cache Poisoning" width="56"/></td><td>
### Web Cache Poisoning
`WebCachePoisoningDetector`

Unkeyed-input cache poisoning via header/parameter probes that check whether a poisoned response is actually served back on a clean request.
</td></tr></table>

<table><tr><td><img src="svg/icon-cachedeception.svg" alt="Web Cache Deception" width="56"/></td><td>
### Web Cache Deception
`WebCacheDeceptionDetector`

Static-extension path confusion that tricks a cache into storing a dynamic, sensitive response.
</td></tr></table>

<table><tr><td><img src="svg/icon-fileupload.svg" alt="Insecure File Upload" width="56"/></td><td>
### Insecure File Upload
`InsecureFileUploadDetector`

Extension/MIME-type bypass attempts and polyglot file detection.
</td></tr></table>

<table><tr><td><img src="svg/icon-log4shell.svg" alt="Log4Shell" width="56"/></td><td>
### Log4Shell
`Log4ShellDetectors`

JNDI lookup injection across common header/parameter injection points, OOB-confirmed.
</td></tr></table>

<table><tr><td><img src="svg/icon-csvinjection.svg" alt="CSV/Formula Injection" width="56"/></td><td>
### CSV/Formula Injection
`CsvFormulaInjectionDetector`

Detects unsanitized formula-prefix characters (`=`, `+`, `-`, `@`) reaching exportable CSV/Excel output.
</td></tr></table>

<table><tr><td><img src="svg/icon-saml.svg" alt="SAML/SSO Security" width="56"/></td><td>
### SAML/SSO Security
`SamlSecurityDetector`

Signature-wrapping and weak-signature checks on SAML assertions.
</td></tr></table>

<table><tr><td><img src="svg/icon-grpc.svg" alt="gRPC-Web / Connect-RPC Security" width="56"/></td><td>
### gRPC-Web / Connect-RPC Security
`GrpcWebSecurityDetector`

Protocol-specific auth and input-validation checks for gRPC-Web and Connect-RPC endpoints.
</td></tr></table>

<table><tr><td><img src="svg/icon-k8s.svg" alt="Kubernetes API Exposure" width="56"/></td><td>
### Kubernetes API Exposure
`KubernetesApiExposureDetector`

Detects exposed Kubernetes API server endpoints reachable through the tested application.
</td></tr></table>

<table><tr><td><img src="svg/icon-webauthn.svg" alt="WebAuthn/FIDO2 Downgrade" width="56"/></td><td>
### WebAuthn/FIDO2 Downgrade
`WebAuthnDowngradeDetector`

Checks whether a WebAuthn flow can be downgraded to a weaker second factor.
</td></tr></table>

<table><tr><td><img src="svg/icon-headers.svg" alt="Security Headers" width="56"/></td><td>
### Security Headers
`SecurityHeadersDetector`

CSP, HSTS, X-Frame-Options, and related header presence/strength (passive).
</td></tr></table>

<table><tr><td><img src="svg/icon-info.svg" alt="Information Disclosure" width="56"/></td><td>
### Information Disclosure
`InfoDisclosureDetector`

Stack traces, debug endpoints, internal IPs, and comment leakage (passive).
</td></tr></table>

---


---

## ⚙️ Layer 3 — Workflow Engine

The stateful foundation everything in Layer 4 is built on — the thing that turns "send one request,
check the response" into "replay this request as a different user, diff the structured result, and
decide if that's actually an authorization bypass."

<table><tr><td><img src="svg/icon-identityregistry.svg" alt="SessionIdentity / IdentityRegistry" width="56"/></td><td>
### SessionIdentity / IdentityRegistry
Named credential sets (Victim / Attacker / Admin / Custom), configured once in the **Identities** tab, reusable by every detector instead of each one inventing its own "secondary session header" setting.
</td></tr></table>

<table><tr><td><img src="svg/icon-objectgraph.svg" alt="ObjectGraph" width="56"/></td><td>
### ObjectGraph
Passively learns `{resourceType: id}` pairs from *every* request URL and JSON response body Burp observes. Feeds REST and GraphQL detectors alike — this is how BOLA replay knows which object IDs exist to try.
</td></tr></table>

<table><tr><td><img src="svg/icon-responsesimilarity.svg" alt="ResponseSimilarityEngine" width="56"/></td><td>
### ResponseSimilarityEngine
Structural JSON diff: same key-shape + types but different data values is the actual signature of a successful authorization bypass, not just "the response changed length."
</td></tr></table>

<table><tr><td><img src="svg/icon-chainguard.svg" alt="WorkflowEngine / ChainGuard" width="56"/></td><td>
### WorkflowEngine / ChainGuard
Chainable, identity-switchable request sequences, gated by Safe Mode, a per-chain request budget, and inter-request throttling — the same guardrail machinery the AI layer reuses.
</td></tr></table>

<img src="svg/diagram-identities.svg" alt="identities diagram"/>

---


---

## 🔗 Layer 4 — Cross-Identity & Chain Detectors

Everything here requires at least one non-default identity configured — see
[Identities & Setup](#-identities--cross-identity-setup).

<table><tr><td><img src="svg/icon-crossidentity.svg" alt="Cross-Identity BOLA/IDOR Replay" width="56"/></td><td>
### Cross-Identity BOLA/IDOR Replay
`CrossIdentityBolaDetector`

Replays a VICTIM's object-scoped request as ATTACKER, using `ObjectGraph`-learned IDs, and applies `ResponseSimilarityEngine` to confirm the ATTACKER genuinely received the VICTIM's data shape.
</td></tr></table>

<table><tr><td><img src="svg/icon-idor.svg" alt="IDOR (single-identity)" width="56"/></td><td>
### IDOR (single-identity)
`IdorAuthorizationDetector`

Sequential/predictable-ID enumeration checks that don't require a second identity — a lighter-weight companion to the cross-identity variant.
</td></tr></table>

<table><tr><td><img src="svg/icon-privesc.svg" alt="Privilege Escalation Chains" width="56"/></td><td>
### Privilege Escalation Chains
`PrivilegeEscalationChainDetector`

Attempts a role/permission change as a lower-privileged identity, then runs a **follow-up self-lookup** to confirm the change actually persisted server-side — not just that the mutating request returned `200 OK`.
</td></tr></table>

<table><tr><td><img src="svg/icon-race.svg" alt="Race Conditions" width="56"/></td><td>
### Race Conditions
`RaceConditionDetector`

Fires concurrent requests at single-use or limited-use endpoints (coupon codes, withdrawal limits) and checks whether more redemptions succeeded than should have been possible.
</td></tr></table>

<table><tr><td><img src="svg/icon-takeover.svg" alt="Account Takeover" width="56"/></td><td>
### Account Takeover
`AccountTakeoverDetector`

Password-reset and account-linking flow abuse — token predictability, host-header-poisoned reset links, and identity-confusion during linking.
</td></tr></table>

<table><tr><td><img src="svg/icon-massassignment.svg" alt="Mass Assignment" width="56"/></td><td>
### Mass Assignment
`MassAssignmentConfirmDetector`

Injects unexpected fields (like `isAdmin: true`) into write requests and **confirms** via follow-up read whether the server actually persisted the extra field.
</td></tr></table>

<table><tr><td><img src="svg/icon-authzbypass.svg" alt="Authorization Bypass" width="56"/></td><td>
### Authorization Bypass
`AuthzBypassDetector`

Method/path-based authorization bypass — verb tampering, trailing-slash/case variants, and header-based auth-check bypasses.
</td></tr></table>

<table><tr><td><img src="svg/icon-businesslogic.svg" alt="Business Logic Abuse" width="56"/></td><td>
### Business Logic Abuse
`BusinessLogicAbuseDetector`

Negative-value tampering (negative quantity → refund) and single-use-code reuse, both requiring the workflow engine's chaining to set up a valid before/after comparison.
</td></tr></table>

<table><tr><td><img src="svg/icon-oauth.svg" alt="OAuth/OIDC Security Suite" width="56"/></td><td>
### OAuth/OIDC Security Suite
`OAuthSecurityDetector`

Redirect URI validation, state-parameter CSRF, PKCE downgrade, and token-leakage-via-referrer checks across the OAuth/OIDC flow.
</td></tr></table>

<table><tr><td><img src="svg/icon-graphql.svg" alt="GraphQL Security Suite" width="56"/></td><td>
### GraphQL Security Suite
`GraphQlSecurityDetector`

Introspection exposure, batching/aliasing-based rate-limit bypass, and object-graph-fed authorization checks specific to GraphQL's single-endpoint model.
</td></tr></table>

<table><tr><td><img src="svg/icon-websocket.svg" alt="WebSocket Security" width="56"/></td><td>
### WebSocket Security
`WebSocketSecurityDetector`

Origin validation and authentication checks specific to the WebSocket handshake and message flow.
</td></tr></table>

<img src="svg/icon-findingscorrelator.svg" alt="correlator" width="64"/>

**`FindingsCorrelator`** raises a consolidated `[CHAIN]` issue when known-chainable finding pairs
(e.g. an IDOR *plus* a mass-assignment on the same host) land together — the whole point being that a
chain is often more severe than the sum of its parts, and a report should say so explicitly.

---


---

## 🤖 Layer 5 — AI-Assisted Features (all opt-in)

Works with any OpenAI-compatible chat completions endpoint (OpenRouter, Cloudflare AI Gateway, a
self-hosted gateway) — configured once in **Settings**, API key held in memory for the session only,
**never persisted or logged**.

<table><tr><td><img src="svg/icon-ai-triage.svg" alt="AI Triage" width="56"/></td><td>
### AI Triage
`AiTriageClient`

One finding's evidence sent on request for a real-vs-false-positive judgment with reasoning. You stay the final decision-maker — this is a second opinion, not an auto-accept/reject switch.
</td></tr></table>

<table><tr><td><img src="svg/icon-ai-chain.svg" alt="AI Chain Synthesis" width="56"/></td><td>
### AI Chain Synthesis
`AiChainSynthesizer`

Sends the full findings set for a host and asks the model to propose multi-step attack-chain hypotheses beyond the built-in `FindingsCorrelator` templates. **Read-only analysis** — proposes for manual review, executes nothing itself.
</td></tr></table>

<table><tr><td><img src="svg/icon-ai-adaptive.svg" alt="AI Adaptive Exploit" width="56"/></td><td>
### AI Adaptive Exploit
`AiAdaptiveExploitEngine`

Multi-turn exploitation attempt against a single finding, with the AI's own claim **cross-checked against `ExploitEvidenceValidator`'s independent, per-category evidence signatures** before anything is classified CONFIRMED.
</td></tr></table>

<table><tr><td><img src="svg/icon-ai-mutator.svg" alt="AI Payload Mutator" width="56"/></td><td>
### AI Payload Mutator
`AiPayloadMutator`

Generates candidate payloads for an insertion point, fires each one, and independently validates the response rather than trusting the AI's own claim of success.
</td></tr></table>

<table><tr><td><img src="svg/icon-ai-recon.svg" alt="AI Recon Agent" width="56"/></td><td>
### AI Recon Agent
`AiReconAgent`

Passive-surface reconnaissance assistant — summarizes observed endpoints, parameters, and technology signals for the host currently in scope.
</td></tr></table>

<table><tr><td><img src="svg/icon-ai-memory.svg" alt="AI Pentest Memory" width="56"/></td><td>
### AI Pentest Memory
`AiPentestMemory`

Session-scoped context store so multi-turn AI features (Adaptive Exploit, Agent Loop) retain what they've already tried against a given target instead of repeating themselves.
</td></tr></table>

<table><tr><td><img src="svg/icon-ai-toolexec.svg" alt="AI Tool Registry / Executor" width="56"/></td><td>
### AI Tool Registry / Executor
`AiToolRegistry · AiToolExecutor`

The tool-calling contract the AI agent uses to actually issue HTTP requests — every tool call still routes through `WorkflowEngine`/`ChainGuard`, so Safe Mode applies exactly as it does to built-in detectors.
</td></tr></table>

<table><tr><td><img src="svg/icon-ai-agentloop.svg" alt="AI Agent Loop" width="56"/></td><td>
### AI Agent Loop
`AiAgentLoop`

The turn-taking loop (observe → reason → act → observe) underneath the higher-level Adaptive Exploit and Autonomous Orchestrator features.
</td></tr></table>

---


---

## 🧠 Layer 6 — Autonomous Exploit Orchestrator

<img src="svg/diagram-orchestrator-loop.svg" alt="orchestrator loop" width="420"/>

`ai/orchestrator/` — a fully autonomous **discover → plan → execute → review** loop across every
unprocessed finding, highest-risk chains first (declared severity, step count, HIGH-severity finding
count, with an in-progress boost for chains already partway through). Respects **Safe Mode**/
**ChainGuard** and a hard action cap, and logs everything it does to `AutonomousRunHistory` for
after-the-fact review.

| Phase | What happens |
|---|---|
| **Discover** | Scans `FindingsStore` for unprocessed findings and ranks candidate chains by risk |
| **Plan** | Builds a step sequence using `WorkflowEngine` primitives, respecting the configured action cap |
| **Execute** | Runs the plan through the same `ChainGuard`-gated request machinery every other detector uses |
| **Review** | Validates outcomes against `ExploitEvidenceValidator`, updates confidence, and records the run in `AutonomousRunHistory` |

**Off by default, and requires you to explicitly click Start** — this is the one feature in the
whole extension that keeps running without a per-action click, so it gets an explicit two-step opt-in
(enable AI in Settings, *then* start Autonomous Mode) rather than a single checkbox.

---


---

## 📜 Custom Rules Engine

<img src="svg/icon-rulesengine.svg" alt="rules engine" width="64"/>

`CustomRuleEngine` + `MiniJson`/`JsonLite`/`JsonUtil` — a hand-written JSON parser (no external
dependency) that loads rule definitions from `src/main/resources/rules/` and lets you extend detection
without touching Java. A rule is a matcher against request/response content plus a severity and a
category tag; **287 rules ship bundled** covering framework-specific misconfigurations, default
credential banners, and vendor-specific information disclosure signatures.

Example rule shape (see `example-rules.json` in the repo root for the full reference):

```json
{
  "id": "exposed-git-directory",
  "category": "INFO_DISCLOSURE",
  "severity": "MEDIUM",
  "match": { "path": "/.git/config", "statusCode": 200 },
  "confidence": "FIRM",
  "description": "Exposed .git directory allows source disclosure."
}
```

Drop custom `.json` rule files into the rules directory and reload the extension — no recompilation
needed.

---


---

## 📊 Confidence System

<img src="svg/diagram-confidence-ladder.svg" alt="confidence ladder"/>
<img src="svg/icon-confidence.svg" alt="confidence" width="64"/>

Every finding is rated on a three-step ladder, and the ladder only moves **up** on independent
evidence — never down through wishful thinking:

- **TENTATIVE** — a single signal fired (e.g. one boolean-blind SQLi differential). Worth
  investigating, not yet worth reporting as-is.
- **FIRM** — an independent confirmation pass (a second, differently-shaped probe, or a workflow-level
  before/after check) agreed with the original signal.
- **CERTAIN** — exploit evidence was independently validated by `ExploitEvidenceValidator` against a
  category-specific signature (a Collaborator interaction, a persisted state change confirmed by a
  follow-up read, a canary token echoed back). This is the only tier AI-driven exploitation is allowed
  to claim on its own say-so — it still has to pass the same validator every built-in detector uses.

---


---

## 🛡️ Safe Mode — Why It Exists

<img src="svg/icon-safemode.svg" alt="safe mode" width="64"/>

<img src="svg/diagram-safemode-gate.svg" alt="safe mode gate"/>

Every detector step is tagged, at the source, as either **read-only** or **mutating**. `ChainGuard`
checks that tag before a step is allowed to fire:

- **Safe Mode ON (default):** read-only steps run normally; any step marked mutating is **blocked**
  and logged as skipped, whether it's a hand-written detector, an AI Adaptive Exploit attempt, or an
  Autonomous Orchestrator action.
- **Safe Mode OFF:** mutating steps are allowed to run — this is what's required for things like
  Race Condition testing, Mass Assignment confirmation, and Business Logic Abuse checks to do
  anything at all, since verifying those *is* a state change by definition.

Turn Safe Mode off only against a target where you have explicit authorization to send
state-mutating test traffic, and ideally against a staging/test environment rather than production.

---


---

## 👤 Identities & Cross-Identity Setup

<img src="svg/diagram-identities.svg" alt="identities"/>

Open the **Identities** tab and configure at minimum:

1. A **VICTIM** identity — session token/cookie for a normal, lower-privileged account.
2. An **ATTACKER** identity — session token/cookie for a second, separate account of the same or
   lower privilege level.
3. Optionally an **ADMIN** identity, if your target has an elevated role you're authorized to test
   privilege-escalation *toward*.

Without at least VICTIM + ATTACKER configured, `CrossIdentityBolaDetector`,
`PrivilegeEscalationChainDetector`, and the Business Logic detectors **silently skip** rather than
erroring — check the Identities tab first if you expect findings from these categories and see none.

---


---

## 🖥️ UI Tour

- <img src="svg/icon-detectorengine.svg" alt="Dashboard" width="32"/> **Dashboard** — Live findings feed as they're raised, filterable by category/confidence/severity.
- <img src="svg/icon-identityregistry.svg" alt="Identities" width="32"/> **Identities** — Configure VICTIM/ATTACKER/ADMIN/Custom identities used by cross-identity detectors.
- <img src="svg/icon-settings.svg" alt="Settings" width="32"/> **Settings** — Toggle detector categories, Safe Mode, AI provider/model/API key, request throttling.
- <img src="svg/icon-ai-orchestrator.svg" alt="Autonomous" width="32"/> **Autonomous** — Start/stop the Autonomous Orchestrator, view its action cap and current run status.
- <img src="svg/icon-history.svg" alt="History" width="32"/> **History** — Every past scan/autonomous run, replayable via `ScanHistoryTracker` / `AutonomousRunHistory`.
- <img src="svg/icon-audit.svg" alt="Audit Log" width="32"/> **Audit Log** — Every request the extension itself sent (not just Burp's own traffic), via `RequestAuditLog`.
- <img src="svg/icon-export.svg" alt="Export" width="32"/> **Export** — Generate an HTML report (`HtmlReportGenerator`) or export raw findings (`FindingsExporter`).

---


---

## 📤 Findings Export

<img src="svg/icon-export.svg" alt="export" width="64"/>

`HtmlReportGenerator` produces a self-contained, client-shareable HTML report grouped by host,
severity, and confidence, with full request/response evidence per finding. `FindingsExporter` handles
machine-readable export (JSON) for feeding into other tooling or a ticketing system integration.

---


---

## 🕓 History, Audit & Suppression

<table><tr><td><img src="svg/icon-history.svg" alt="ScanHistoryTracker / AutonomousRunHistory" width="56"/></td><td>
### ScanHistoryTracker / AutonomousRunHistory
Every scan and every autonomous run is recorded and browsable after the fact — what ran, what was found, what the orchestrator decided and why.
</td></tr></table>

<table><tr><td><img src="svg/icon-audit.svg" alt="RequestAuditLog" width="56"/></td><td>
### RequestAuditLog
A complete log of every request the *extension itself* originated (as distinct from your own manual Burp traffic) — essential for after-action review of what an autonomous run actually did.
</td></tr></table>

<table><tr><td><img src="svg/icon-classifier.svg" alt="FindingsSuppressionEngine" width="56"/></td><td>
### FindingsSuppressionEngine
Mark a finding (or a whole category, on a given host) as suppressed — accepted risk, known false positive, out of scope — so it stops resurfacing on every re-scan.
</td></tr></table>

---


---

## ⚙️ Configuration Reference

| Setting | Default | Notes |
|---|---|---|
| Safe Mode | **ON** | Blocks every mutating step. See [Safe Mode](#️-safe-mode--why-it-exists). |
| AI features | **OFF** | Requires an OpenAI-compatible endpoint URL + API key, set per session, never persisted. |
| Autonomous Mode | **OFF** | Requires AI enabled *and* an explicit Start click. Has a hard action cap. |
| Detector categories | **All ON** | Toggle individually in Settings if you want to scope a scan (e.g. passive-only). |
| Request throttling | Configurable | Inter-request delay used by `WorkflowEngine` chains and the Autonomous Orchestrator. |
| Collaborator | Uses Burp's own | OOB detectors (SSRF, SSTI-blind, Log4Shell, XXE) reuse Burp's configured Collaborator server. |

---


---

## 🗂️ Project Layout

```text
lawcybug/
├── pom.xml
├── README.md
├── CHANGELOG.md
├── EULA.md
├── example-rules.json
├── docs/
│   ├── svg/                  # every diagram + icon used in this README
│   └── img/                  # (reserved for additional screenshots)
└── src/
    ├── main/java/pro/lawcybug/scanner/
    │   ├── core/             # DetectorEngine, ActiveDetector/PassiveDetector, IssueFactory, Finding
    │   ├── detectors/        # 30+ classic + chain detector packages (sqli/, xss/, ssrf/, bola/, ...)
    │   ├── workflow/         # SessionIdentity, ObjectGraph, ResponseSimilarityEngine, ChainGuard
    │   ├── ai/               # Triage, ChainSynthesizer, AdaptiveExploit, PayloadMutator, 
    │   │   ├── orchestrator/ #   Autonomous discover→plan→execute→review loop
    │   │   ├── recon/        #   AiReconAgent
    │   │   ├── tools/        #   AiToolRegistry / AiToolExecutor
    │   │   └── memory/       #   AiPentestMemory
    │   ├── rules/            # CustomRuleEngine, MiniJson/JsonLite/JsonUtil
    │   ├── history/          # ScanHistoryTracker, AutonomousRunHistory
    │   ├── audit/            # RequestAuditLog
    │   ├── export/           # HtmlReportGenerator, FindingsExporter
    │   ├── profile/          # EngagementProfile
    │   ├── classification/   # EndpointClassifier, VulnCategoryMapper
    │   ├── learning/         # passive learning support for ObjectGraph-adjacent detectors
    │   ├── autoexploit/      # AutoExploitEngine, AiAdaptiveExploitEngine wiring
    │   ├── ui/               # LawCyBugTab and all Burp UI panels
    │   └── util/             # shared helpers
    ├── main/resources/rules/ # 287 bundled JSON rule definitions
    └── test/                 # JUnit 5 test suite
```

---


---

## 🔬 Step-by-Step: How a Scan Actually Runs

A concrete walkthrough, from opening Burp to seeing a finding, for someone who wants to understand
the mechanics rather than just the feature list:

**1. Load the extension**  
Burp calls `LawCyBugExtension`'s entry point, which registers the `LawCyBugTab` UI, initializes `DetectorEngine` with every detector package, and wires up `FindingsStore`, `ScanHistoryTracker`, and `RequestAuditLog`.

**2. Traffic starts flowing**  
As you browse through Burp's Proxy (or run Burp's own Scanner, or send from Repeater — configurable in Settings), each request/response pair is handed to `DetectorEngine.process(...)`.

**3. Passive pass**  
Every enabled `PassiveDetector` inspects the pair immediately — this includes `ObjectGraph` silently learning `{resourceType: id}` pairs in the background, whether or not any cross-identity detector is enabled yet.

**4. Active pass (if enabled)**  
Enabled `ActiveDetector`s decide, per request, whether it's a plausible target (via `EndpointClassifier`) and if so fire their own probe requests — gated through `ChainGuard` if the probe is tagged mutating.

**5. Evidence validation**  
Any raw signal — an error string, a timing delta, a Collaborator interaction — is checked against `ExploitEvidenceValidator`'s category-specific signature before it's allowed to become a `Finding` at all. This is what prevents "the response was 40ms slower" alone from becoming a SQLi finding.

**6. Confidence assignment**  
The new finding starts at TENTATIVE, or FIRM/CERTAIN immediately if the detector's confirmation pass already ran (see the Confidence System section).

**7. Correlation**  
`FindingsCorrelator` checks whether this finding, combined with anything already known on the same host, matches a known chainable pattern — if so, a `[CHAIN]` finding is raised alongside the individual one.

**8. Suppression check**  
`FindingsSuppressionEngine` checks whether this exact finding (or its category on this host) was previously suppressed — if so it's recorded but not surfaced again in the live feed.

**9. Storage & display**  
The finding lands in `FindingsStore` and appears immediately in the Dashboard tab, filterable by category, confidence, and severity.

**10. Optional: AI Triage**  
You can select any TENTATIVE finding and request `AiTriageClient` review — it receives the finding's evidence and returns a real-vs-false-positive judgment with reasoning, entirely on request.

**11. Optional: Autonomous follow-up**  
If Autonomous Mode is running, unprocessed findings are periodically picked up by the Orchestrator, ranked, and — within Safe Mode and the action cap — worked through the discover→plan→execute→review loop described in Layer 6.

---


---

## 📦 Detector Package Census

A full accounting of every package under `src/main/java/pro/lawcybug/scanner/detectors/`, for anyone
auditing coverage against their own checklist:

| Package | Coverage |
|---|---|
| `detectors/sqli/` | SQL injection — error, boolean-blind, time-based |
| `detectors/xss/` | Reflected cross-site scripting, context-aware |
| `detectors/cmdi/` | Blind OS command injection |
| `detectors/ssrf/` | Server-side request forgery, Collaborator-confirmed |
| `detectors/cors/` | CORS misconfiguration |
| `detectors/headers/` | Security header presence/strength (passive) |
| `detectors/redirect/` | Open redirect |
| `detectors/jwt/` | JWT misconfiguration |
| `detectors/xxe/` | XML external entity injection |
| `detectors/deserial/` | Insecure deserialization |
| `detectors/traversal/` | Path traversal |
| `detectors/hostheader/` | Host header injection |
| `detectors/crlf/` | CRLF / header injection |
| `detectors/smuggling/` | HTTP request smuggling (HTTP/1.1) |
| `detectors/h2smuggling/` | HTTP/2 downgrade smuggling |
| `detectors/hpp/` | HTTP parameter pollution |
| `detectors/xpath/` | XPath injection |
| `detectors/nosql/` | NoSQL injection |
| `detectors/ldap/` | LDAP injection |
| `detectors/protopollution/` | Prototype pollution |
| `detectors/cachepoisoning/` | Web cache poisoning |
| `detectors/cachedeception/` | Web cache deception |
| `detectors/fileupload/` | Insecure file upload |
| `detectors/log4shell/` | Log4Shell / JNDI injection |
| `detectors/csvinjection/` | CSV/formula injection |
| `detectors/saml/` | SAML/SSO security |
| `detectors/grpc/` | gRPC-Web / Connect-RPC security |
| `detectors/k8s/` | Kubernetes API exposure |
| `detectors/webauthn/` | WebAuthn/FIDO2 downgrade |
| `detectors/info/` | Information disclosure (passive) |
| `detectors/bola/` | Cross-identity BOLA/IDOR replay |
| `detectors/idor/` | Single-identity IDOR |
| `detectors/atochain/` | Account takeover chains |
| `detectors/race/` | Race conditions |
| `detectors/massassignment/` | Mass assignment |
| `detectors/authzbypass/` | Authorization bypass |
| `detectors/businesslogic/` | Business logic abuse |
| `detectors/oauth/` | OAuth/OIDC security suite |
| `detectors/graphql/` | GraphQL security suite |
| `detectors/websocket/` | WebSocket security |

**40 detector packages**, matching the headline count — some packages contain more than
one detector class (e.g. `xxe/` holds several `XxeDetectors` variants), which is why the Java-file
count under `detectors/` is higher than the package count.

---


---

## 🧭 Glossary

| Term | Meaning |
|---|---|
| **Finding** | A single reported issue — category, severity, confidence, evidence, and the request/response that produced it. |
| **Chain** | Two or more findings that, combined, represent a more severe issue than either alone — raised as a `[CHAIN]` finding by `FindingsCorrelator`. |
| **Identity** | A named credential set (session token/cookie) representing one user account, configured in the Identities tab. |
| **Object Graph** | The passively-learned map of `{resourceType: id}` pairs `ObjectGraph` builds from observed traffic. |
| **Safe Mode** | The global switch that blocks any detector step tagged as state-mutating. |
| **Confidence** | TENTATIVE / FIRM / CERTAIN — how independently confirmed a finding's evidence is. |
| **ChainGuard** | The component that enforces Safe Mode, request budgets, and throttling on every multi-step workflow, built-in or AI-driven. |
| **Autonomous Mode** | The orchestrator's self-driving discover→plan→execute→review loop, off by default. |
| **Rule** | A JSON-defined match pattern loaded by `CustomRuleEngine`, extending detection without new Java code. |

---


---

## 🛠️ Troubleshooting

**Build fails with dependency resolution errors**  
Confirm outbound access to Maven Central (`repo1.maven.org`) from your build machine — the sandbox this project was authored in has none, which is why the shipped jar should be treated as a convenience copy, not a verified release artifact.

**Extension loads but the tab is empty**  
Confirm you're on a Montoya-API-compatible Burp version — check `montoya.version` in `pom.xml` against your Burp Suite's supported API version.

**No findings at all after browsing**  
Check Settings — confirm the relevant detector categories are enabled and that Burp is actually routing traffic through the Proxy listener the extension is observing.

**Cross-identity detectors produce nothing**  
See the Identities section above — this category requires explicit VICTIM/ATTACKER setup and silently skips otherwise.

**AI features do nothing when clicked**  
Confirm an API key and a valid OpenAI-compatible endpoint URL are set in Settings — the AI layer makes no network calls at all until both are present and a specific AI action is triggered.

---


---

## 🗺️ Roadmap

See `CHANGELOG.md` for full version history. High-level direction:

- [ ] Expand the bundled rule set beyond 287 rules
- [ ] Additional AI-provider-specific prompt tuning for smaller local models
- [ ] Deeper GraphQL query-cost / batching abuse detection
- [ ] Richer HTML report theming and diff-view for re-scans

---


---

## 🏷️ Version & Acknowledgments

Current build: **`1.34.5`** (see `<version>` in `pom.xml`). Full history — including a `mvn clean
package` run that caught two real, previously-latent bugs (`AiPentestMemory.clearSession()` and
`AutonomousRunHistory.toMarkdown()` run numbering) — is in `CHANGELOG.md`.

Built on the [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/) provided by
PortSwigger's Burp Suite. No other runtime dependencies — the JSON handling (`MiniJson` / `JsonLite` /
`JsonUtil`) and the rules engine are hand-written specifically to keep this a zero-dependency, single-jar
extension.

---

<div align="center">

<img src="svg/banner-footer.svg" alt="LawCyBUG.pro footer"/>

*Made for people who have permission to break things.*

</div>

---

<div align="center">

[← back to README](../README.md)

<img src="svg/banner-footer.svg" alt="LawCyBUG.pro footer"/>

</div>