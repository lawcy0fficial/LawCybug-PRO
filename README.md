<div align="center">

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██╗      █████╗ ██╗    ██╗ ██████╗██╗   ██╗██████╗ ██╗   ██╗ ██████╗   ║
║    ██║     ██╔══██╗██║    ██║██╔════╝╚██╗ ██╔╝██╔══██╗██║   ██║██╔════╝   ║
║    ██║     ███████║██║ █╗ ██║██║      ╚████╔╝ ██████╔╝██║   ██║██║  ███╗  ║
║    ██║     ██╔══██║██║███╗██║██║       ╚██╔╝  ██╔══██╗██║   ██║██║   ██║  ║
║    ███████╗██║  ██║╚███╔███╔╝╚██████╗   ██║   ██████╔╝╚██████╔╝╚██████╔╝  ║
║    ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝   ╚═╝   ╚═════╝  ╚═════╝  ╚═════╝  ║
║                                                                              ║
║                  ·  P  R  O  ·  v  0  .  1  .  0  -    ·     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

# 🕷️ The Bug Hunter's Weapon of Choice 🕷️

### *"Others scan. You hunt."*

<br>

[![Version](https://img.shields.io/badge/⚡_VERSION-v0.2.0--tier1-00ff88?style=for-the-badge)](.)
[![API](https://img.shields.io/badge/🔥_MONTOYA_API-2026.4-ff6b35?style=for-the-badge)](.)
[![JDK](https://img.shields.io/badge/☕_JDK-17%2B-4ecdc4?style=for-the-badge)](.)
[![Build](https://img.shields.io/badge/🔨_BUILD-Maven-c0392b?style=for-the-badge)](.)
[![Rules](https://img.shields.io/badge/📜_RULES-287_Bundled-9b59b6?style=for-the-badge)](.)
[![Detectors](https://img.shields.io/badge/🎯_DETECTORS-16_Active_·_7_Passive-e74c3c?style=for-the-badge)](.)
[![Lines](https://img.shields.io/badge/💀_SOURCE-~3500_Lines_of_Java-2c3e50?style=for-the-badge)](.)

<br>

> 🩸 *Built for authorized security testing & bug bounty programs only* 🩸

</div>

<br>

---

```
  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  ░                                                                     ░
  ░   Every vulnerability has a heartbeat. LawCyBug.pro finds it.      ░
  ░                                                                     ░
  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

---

## 🌑 · W H A T · I S · T H I S · 🌑

**LawCyBug.pro** is not a scanner. It is a *predator*.

A hand-crafted, enterprise-grade **Burp Suite Professional extension** built on the Montoya API — forged from scratch in raw Java, with zero dependencies, zero compromises, and a single obsession: **confirmed findings, not noise**.

While other tools throw generic payloads at walls and pray, LawCyBug.pro runs **three-way statistical diffing**, **out-of-band Collaborator callbacks**, **two-step chain verification**, and **cross-identity object graph replay** before it dares raise a single finding.

This is not a wrapper. Not a GUI skin. Not a YAML rule importer with a logo.

Every detector was written from first principles, for a single audience:

> **The hunter who needs to be right.**

<br>

| 🎯 Pillar | ⚡ What It Means |
|:---:|:---|
| 🔬 **Confirmed over Noisy** | Statistical timing · 3-way response diff · OOB callbacks · chain verification |
| 🕸️ **Modern Attack Surface** | GraphQL · OAuth 2.0/OIDC · BOLA · Race Conditions · Business Logic · Priv-Esc Chains |
| 💀 **Zero False-Positive Tolerance** | Every HIGH/CRITICAL ships with exact evidence a bounty report needs |
| 🧬 **Extensible Without Java** | 287 bundled JSON rules + write your own, live, no rebuild |

---

## 🗺️ · T A B L E · O F · C O N T E N T S · 🗺️

```
  ┌─────────────────────────────────────────────────────────────┐
  │  01  ·  Architecture — The Blueprint                        │
  │  02  ·  Active Detectors — The Hunters                      │
  │  03  ·  Passive Detectors — The Watchers                    │
  │  04  ·  Advanced Engine — The Brain                         │
  │  05  ·  Custom Rule Engine — 287 Rules of Power             │
  │  06  ·  Burp UI — The Command Center                        │
  │  07  ·  Building & Loading — Forging the Weapon             │
  │  08  ·  Setup & Configuration — Arming the Hunter           │
  │  09  ·  Project Structure — The Anatomy                     │
  │  10  ·  Ethical Use — The Code                              │
  └─────────────────────────────────────────────────────────────┘
```

---

<br>

## 🏛️ 01 · A R C H I T E C T U R E · — · T H E · B L U E P R I N T

```
 ╔══════════════════════════════════════════════════════════════════════╗
 ║                    🔱  BURP SUITE PROFESSIONAL  🔱                  ║
 ║                                                                      ║
 ║   HTTP Traffic ──────────────────► LawCyBugExtension.java           ║
 ║                                           │                          ║
 ║                          ┌────────────────┼────────────────┐         ║
 ║                          ▼                ▼                ▼         ║
 ║                   ┌─────────────┐  ┌───────────┐  ┌──────────────┐ ║
 ║                   │ Detector    │  │ Findings  │  │   UI  Tab    │ ║
 ║                   │ Engine      │  │  Store    │  │  🖥️ Dashboard │ ║
 ║                   └──────┬──────┘  └─────┬─────┘  │  ⚙️ Settings  │ ║
 ║                          │               │        │  📝 Rules     │ ║
 ║              ┌───────────┴──────────┐    │        └──────────────┘ ║
 ║              ▼                      ▼    │                          ║
 ║      ┌──────────────┐    ┌────────────┐  │                          ║
 ║      │  🔴 ACTIVE   │    │ 🟡 PASSIVE │  │                          ║
 ║      │  Detectors   │    │ Detectors  │  │                          ║
 ║      │  (16 total)  │    │  (7 total) │  │                          ║
 ║      └──────┬───────┘    └─────┬──────┘  │                          ║
 ║             │                  │         │                          ║
 ║             └──────────────────┘         │                          ║
 ║                       │                  │                          ║
 ║             ┌──────────────────┐   FindingsCorrelator               ║
 ║             │ CustomRuleEngine │   ⛓️  Chain Detection               ║
 ║             │  287 bundled     │                                     ║
 ║             │   + N manual     │                                     ║
 ║             └──────────────────┘                                     ║
 ╚══════════════════════════════════════════════════════════════════════╝
```

The extension registers itself as a native **`ScanCheck`** with Burp's scanner. It doesn't fight Burp — it *extends* it, invisibly, seamlessly, surgically.

The **`DetectorContext`** is the single shared nerve wire that gives every detector access to everything it needs:
the Montoya API · `ScanSettings` · `FindingsStore` · `CollaboratorClient` · `IdentityRegistry`.

One wire. Sixteen hunters. Seven watchers. Zero noise.

---

<br>

## 🔴 02 · A C T I V E · D E T E C T O R S · — · T H E · H U N T E R S

> *Active detectors don't wait. They reach into the target and pull the truth out.*

Each detector fires only against insertion points it was born for. No spray-and-pray. No wasted requests. Surgical precision on every probe.

---

### 🩸 `[ 01 ]` · SQL INJECTION · *The Classic Killer — Three Ways to Bleed*

> `SqlErrorBasedDetector` · `SqlBooleanBasedDetector` · `SqlTimeBasedDetector` · `SqlPayloads`

SQLi isn't one bug. It's three. And LawCyBug.pro hunts all three independently.

**🔴 Error-Based** — The loud kill. Injects payloads that rip database-native error strings out of the response. One regex match against a known signature and it's confirmed. No timing. No guesswork. MySQL screams. Oracle bleeds. PostgreSQL breaks. It's over.

**🟡 Boolean-Blind — 3-Way Response Diffing** — The quiet kill. Uses `ResponseDiff` to run three requests and compare their structural DNA:

```
  ┌──────────────────────────────────────────────┐
  │  Baseline  ──── original, untouched          │
  │  TRUE      ──── ' AND '1'='1  (must match)   │
  │  FALSE     ──── ' AND '1'='2  (must differ)  │
  │                                              │
  │  Finding raised ONLY when:                   │
  │    diff(baseline, TRUE)  < threshold  ✓      │
  │    diff(baseline, FALSE) > threshold  ✓      │
  └──────────────────────────────────────────────┘
```

If the TRUE payload looks identical to baseline but FALSE causes divergence — the database is listening. This eliminates every false positive that plagues naive "did the page change" boolean checkers.

**⏱️ Time-Based Blind — Statistical Confirmation** — The patient kill. Sends `SLEEP()` / `WAITFOR DELAY` / `pg_sleep()` across every major dialect and uses `TimingUtils` to statistically confirm the delay across multiple retests against baseline. A single slow response is **never** flagged. Only a *consistently* delayed one.

```
  Engines:  MySQL · MSSQL · PostgreSQL · Oracle · SQLite
  Method:   ≥ 3 retests · σ-normalized · baseline-subtracted
```

---

### 🎭 `[ 02 ]` · REFLECTED XSS · *Two-Phase Context Warfare*

> `ReflectedXssDetector`

Naive XSS scanners throw `<script>alert(1)</script>` at every parameter and hope the page breaks. This is not that.

**Phase 1 — Context Reconnaissance:** A unique canary token is injected first. The detector surgically examines *where* it lands in the DOM:

```
  ● Raw HTML body        →  HTML context
  ● Inside tag attribute →  ATTRIBUTE context
  ● Inside <script>      →  SCRIPT context
  ● Inside <!-- -->      →  COMMENT context
```

**Phase 2 — Precision Strike:** A perfectly shaped payload is crafted for the exact context detected:

```
  HTML       →  <img src=x onerror=alert(document.domain)>
  ATTRIBUTE  →  "><svg onload=alert(document.domain)>
  SCRIPT     →  ';alert(document.domain);//
  COMMENT    →  --><svg onload=alert(document.domain)>
```

A finding is only raised when Phase 2's shaped payload is **confirmed as rendered** — not just echoed back in a string.

---

### 💻 `[ 03 ]` · BLIND OS COMMAND INJECTION · *The Shell Whisperer*

> `BlindCommandInjectionDetector`

No error messages. No output. Just silence — and a pause that tells everything.

Time-based blind detection across every major execution environment:

| 🖥️ Platform | 💉 Payload Style |
|:---:|:---|
| POSIX — bash / sh | `; sleep 9;` · `\|\| sleep 9 \|\|` · `` `sleep 9` `` |
| Windows — cmd.exe | `& timeout /t 9 &` · `\| timeout /t 9` |
| PowerShell | `; Start-Sleep 9;` · `\| Start-Sleep -s 9` |

Same `TimingUtils` statistical engine as SQLi. The shell sleeps. The clock tells the truth.

---

### 🌐 `[ 04 ]` · SSRF · *The Server That Calls Home*

> `SsrfCollaboratorDetector`

This detector doesn't guess. It *proves*.

A unique Burp Collaborator payload is generated for each probe and injected into every URL-shaped parameter and header. The finding is raised only when Burp's Collaborator server records an **actual DNS resolution or HTTP callback** from the target infrastructure — irrefutable proof that the server reached out to attacker-controlled infrastructure.

```
  Injection targets:   URL parameters · Host headers · Referer · X-Forwarded-For
  Confirmation:        Real DNS callback + HTTP interaction via Collaborator
  Evidence:            Full interaction log shipped with every finding
```

> 🔑 *Requires Burp Suite Professional + Collaborator configured. Silently stands down on Community Edition — no errors, no ghost findings.*

---

### 🧩 `[ 05 ]` · SERVER-SIDE TEMPLATE INJECTION · *Math That Shouldn't Exist*

> `SstiDetector`

If `{{7*7}}` comes back as `49`, something is very wrong — and very exploitable.

Arithmetic-confirmation payloads across **10 template engines**:

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Jinja2  ·  Twig  ·  Smarty  ·  FreeMarker  ·  Velocity    │
  │  Pebble  ·  Thymeleaf  ·  Mako  ·  Handlebars  ·  ERB      │
  └──────────────────────────────────────────────────────────────┘
```

Engine-specific syntax tested: `{{7*7}}` · `${7*7}` · `<%= 7*7 %>` · `#{7*7}` · `[#assign x=7*7]${x}`

A finding is raised only when `49` appears in the **exact context** of the injection point — not elsewhere on the page.

---

### 🔓 `[ 06 ]` · OAuth 2.0 / OIDC · *Where Identities Bleed*

> `OAuthSecurityDetector` — Active + Passive

The OAuth flow is where identity breaks. LawCyBug.pro targets `authorize`, `callback`, and `token` endpoints specifically — not generic traffic — because these checks are meaningless everywhere else.

| 🎯 Check | 🔬 Mode | 💣 Severity |
|:---|:---:|:---:|
| Missing / predictable `state` — OAuth CSRF | Passive | 🔴 HIGH |
| Missing PKCE `code_challenge` on public clients | Passive | 🟠 MEDIUM |
| Auth code / access token leaking into `Referer` | Passive | 🔴 HIGH |
| `redirect_uri` accepted with loose / open match | **Active Probe** | 🚨 CRITICAL |
| Implicit flow `response_type=token` in use | Passive | 🟠 MEDIUM |

The `redirect_uri` active check is surgical: it replays the authorize request with a subtly modified destination — subdomain swap, path append, URL encoding bypass, scheme confusion — and confirms whether the server still hands over a token to the wrong address.

---

### 🕸️ `[ 07 ]` · GRAPHQL SECURITY · *The Schema That Leaks Secrets*

> `GraphQlSecurityDetector` — Active + Passive

GraphQL is not HTTP. Most scanners treat it like it is. This one doesn't.

Auto-fingerprints GraphQL endpoints from traffic heuristics, then runs a precision check suite against confirmed endpoints only:

| 🔍 Check | 🔬 Mode |
|:---|:---:|
| Introspection enabled on production-looking endpoints | Passive + Active |
| Query batching accepted — DoS / auth-bypass amplification | Active |
| Field aliasing / duplication — query-cost bypass | Active |
| Excessive query depth accepted without limit | Active |
| `__typename` / suggestion leakage when introspection disabled | Active |
| GET-based GraphQL — CSRF attack surface | Passive |
| Missing Content-Type enforcement | Passive |

---

### 🆔 `[ 08 ]` · IDOR / BOLA · *The Object That Forgets Its Owner*

> `IdorAuthorizationDetector` · `CrossIdentityBolaDetector`

Two complementary engines. Both confirm, neither guess.

**`IdorAuthorizationDetector`** — Direct confirmation. Replays a victim's exact request under the attacker's session. If the attacker receives the victim's data — confirmed BOLA. Not "the parameter looks like an ID." *Actual data returned to the wrong identity.*

**`CrossIdentityBolaDetector`** — Object-graph-driven. The passive facet silently builds an `ObjectGraph` from *all* proxied traffic — `URL → {resourceType, resourceId}` — at zero cost, zero extra requests. The active facet then replays cross-identity and uses `ResponseSimilarityEngine` to score whether the attacker received meaningfully similar data — not a differently-shaped 200 OK error page wearing a success costume.

```
  Setup:  Log in as Victim in browser A · Log in as Attacker in browser B
          Paste Attacker session token into Settings → Identity Registry
          Scan any Victim request — detectors replay it as Attacker automatically
```

---

### 🏃 `[ 09 ]` · RACE CONDITIONS · *When Time Is the Vulnerability*

> `RaceConditionDetector`

Some bugs can't be found by looking at one request. They only exist in the gap between two.

LawCyBug.pro implements James Kettle's **last-byte sync / barrier-burst technique**:

```
  Step 1  ──  Build N identical copies of the target request
  Step 2  ──  Submit all to a thread pool behind a CountDownLatch barrier
  Step 3  ──  Fire simultaneously — as close as the JVM allows
  Step 4  ──  Count how many returned a state-changing success
  Step 5  ──  If more than one won where only one should — RACE CONDITION
```

Only fires against insertion points that look like single-use resources: coupon codes · vote endpoints · wallet operations · invite links. Idempotent GETs are ignored.

---

### 👑 `[ 10 ]` · PRIVILEGE ESCALATION CHAIN · *The Role That Shouldn't Exist*

> `PrivilegeEscalationChainDetector`

Two steps. Because one step proves nothing.

**Step 1 — The Injection** *(Mutating — Safe Mode aware)*: Merges privileged fields into the JSON body and fires the request as the Victim:

```json
"role":"admin"  ·  "isAdmin":true  ·  "is_admin":true
"permissions":["*"]  ·  "roleId":1  ·  "groups":["administrators"]
```

**Step 2 — The Verification** *(Read-only)*: Immediately follows with `GET /me` as the *same identity*. Checks whether the privileged value actually *persisted* server-side.

A finding is raised only when **Step 2 confirms the role change took effect** — not when the API merely echoes the injected field in Step 1's response (which every API does, regardless of whether it did anything with it).

> *This is what separates real mass-assignment findings from the mountains of false positives most scanners produce.*

---

### 🧮 `[ 11 ]` · BUSINESS LOGIC ABUSE · *The Bug the Rules Can't See*

> `BusinessLogicAbuseDetector`

Some vulnerabilities cannot be expressed in payload/regex. The application is doing exactly what you asked — and that's the problem.

**💸 Negative-Value Tampering:** Flips `quantity`, `price`, `amount`, `total` fields negative on cart/order/wallet/transfer endpoints. A naive `total = price × quantity` lets a negative quantity reduce a bill below zero. A negative `amount` on a transfer endpoint reverses the direction of money flow.

**🎟️ Sequential Coupon Reuse:** Replays coupon/voucher application back-to-back (non-concurrent) to catch cases where the server never marks a single-use code as consumed at all — distinct from race condition bugs where it marks it consumed *too slowly*. Both are real bug classes. Both pay. Both need different proof.

Uses `ChainGuard` Safe Mode — these detectors change real state. Enable them only when your engagement scope permits.

---

### 🔀 `[ 12 ]` · AUTHORIZATION BYPASS · *Every Door Has a Back Window*

> `AuthzBypassDetector`

Tests every classic and modern ACL bypass technique:

```
  HTTP method override      →  X-HTTP-Method-Override: DELETE · _method=PUT
  Path traversal             →  /api/admin/../user · /api//admin/
  Case manipulation          →  /API/Admin · /api/ADMIN
  Parent path rewind         →  /api/v1/user → /api/v1/admin
  Header-based access        →  X-Original-URL · X-Forwarded-For: 127.0.0.1
```

---

### 📇 `[ 13 ]` · MASS ASSIGNMENT · *The Field That Should Not Be Writeable*

> `MassAssignmentConfirmDetector`

Single-request mass assignment detection targeting JSON body parameters. Injects a curated set of sensitive field candidates and reads the response for acceptance signals — field echoed, no validation error, response body diverges from baseline. Distinct from the privilege escalation chain: this catches simpler cases that don't need a verification step.

---

### 🔑 `[ 14 ]` · ACCOUNT TAKEOVER DETECTION · *The Session That Changes Hands*

> `AccountTakeoverDetector`

Targets password reset, email change, and 2FA bypass flows. Detects predictable token patterns, token reuse across sessions, host header injection in reset-email generation, and missing origin validation on sensitive account-mutation endpoints.

---

### 🌍 `[ 15 ]` · OPEN REDIRECT · *Every Link Is a Loaded Gun*

> `OpenRedirectDetector`

Four redirect mechanisms. Dozens of bypass techniques.

```
  Redirect types:    Location header · meta http-equiv refresh · JS window.location
  Bypass techniques: //evil.com · \/\/evil.com · %2F%2Fevil.com
                     javascript:// · Unicode normalization · scheme confusion
```

---

### 🌐 `[ 16 ]` · CORS MISCONFIGURATION · *The Trust That Goes Both Ways*

> `CorsDetector` — Active + Passive

| ☠️ Attack | 🔬 Probe |
|:---|:---|
| Origin reflection | Sends arbitrary `Origin:` header — checks if reflected in `ACAO` |
| Null-origin bypass | `Origin: null` — accepted by legacy CDN/cache configs |
| Wildcard + credentials | `ACAO: *` + `ACAC: true` — the classic misconfiguration |
| Prefix / suffix bypass | `Origin: evil.trusted-domain.com` — weak `startsWith` ACL |

---

### 🔐 `[ PASSIVE-ACTIVE ]` · JWT MISCONFIGURATION · *The Token With No Spine*

> `JwtMisconfigDetector` — Active + Passive

| 💀 Attack | 🔬 Technique |
|:---|:---|
| `alg:none` forgery | Strips signature · sets `"alg":"none"` in header |
| Empty signature bypass | Submits `header.payload.` with empty third segment |
| Token in URL *(passive)* | Flags JWT values appearing in query parameters |
| Structural issues *(passive)* | Weak `HS256` on RS key · missing `exp` claim |

---

<br>

## 🟡 03 · P A S S I V E · D E T E C T O R S · — · T H E · W A T C H E R S

> *They don't ask questions. They listen to everything — and remember everything.*

Passive detectors analyze all traffic Burp has already proxied. Zero additional requests. Zero footprint. Maximum intelligence.

---

### 🛡️ SECURITY HEADERS AUDIT · *The Missing Armour*

> `SecurityHeadersDetector`

Every HTTP response is audited. No exceptions.

| 🔒 Header | 🔬 What's Checked |
|:---|:---|
| `Content-Security-Policy` | Present · no `unsafe-inline` / `unsafe-eval` / wildcard `*` |
| `Strict-Transport-Security` | Present · `max-age` ≥ 6 months · `includeSubDomains` set |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` — not the deprecated `ALLOW-FROM` |
| `Referrer-Policy` | `no-referrer` or `strict-origin` variants enforced |
| `Permissions-Policy` | Camera · microphone · geolocation locked down |
| `X-Content-Type-Options` | `nosniff` present |

---

### 🕵️ INFORMATION DISCLOSURE · *The Secret That Slipped*

> `InfoDisclosureDetector`

Hunts high-value secrets and debug artifacts in every response body:

```
  🔑  AWS Access Keys      →  AKIA[0-9A-Z]{16}
  🐙  GitHub Tokens        →  ghp_[A-Za-z0-9]{36}
  🤖  OpenAI API Keys      →  sk-[A-Za-z0-9]{48}
  🌐  Google API Keys      →  AIza[0-9A-Za-z\-_]{35}
  💬  Slack Tokens         →  xox[baprs]-([0-9a-zA-Z]{10,48})
  🔐  PEM Private Keys     →  -----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----
  💥  Stack Traces         →  NullPointerException · Traceback · Fatal error
  📁  Internal Paths       →  /etc/passwd · C:\inetpub · /var/www
  🔧  Debug Panels         →  /_profiler · /debug · phpinfo() · __debug__
```

---

<br>

## 🧠 04 · A D V A N C E D · E N G I N E · — · T H E · B R A I N

> *The intelligence layer that turns individual findings into attack narratives.*

---

### ⛓️ FINDINGS CORRELATOR · *When Two Bugs Become One Weapon*

> `FindingsCorrelator`

Watches `FindingsStore` as findings arrive. Automatically detects when two individual findings — together — form a **known attack chain** that's worth far more than either alone:

| ⚔️ Chain Name | 🔗 Components | 💣 Combined Impact |
|:---|:---|:---:|
| OAuth Token Theft | Open Redirect + OAuth on same host | 🚨 CRITICAL |
| Auth Bypass → Data Exfil | CORS Misconfiguration + IDOR | 🚨 CRITICAL |
| Persistent XSS + CSRF | Stored XSS + missing CSRF | 🔴 HIGH |
| SQLi → Account Takeover | SQLi on auth endpoint + Login form | 🚨 CRITICAL |

Chain findings are **additive** — originals still stand. The chain issue is a third, higher-level finding that tells you: *look at these two together first. This is your lead.*

---

### 🔁 WORKFLOW ENGINE · *Attack Flows, Not Attack Points*

> `WorkflowEngine`

Executes named, multi-step HTTP sequences where later steps reference values extracted from earlier responses. Real attack flows. Not single-request probes.

```
  Step 1  →  POST /api/register           extract: userId from "data.user.id"
  Step 2  →  GET  /api/users/{userId}     confirm own data accessible ✓
  Step 3  →  [switch to Attacker identity]
  Step 4  →  GET  /api/users/{userId}     confirm attacker receives victim data ✗
             └── BOLA CONFIRMED ──────────────────────────────────────────────►
```

Used by: `PrivilegeEscalationChainDetector` · `BusinessLogicAbuseDetector` · `CrossIdentityBolaDetector`

---

### 🧠 RESPONSE SIMILARITY ENGINE · *Is This Really the Same Data?*

> `ResponseSimilarityEngine`

Token-level structural comparison of HTTP responses — immune to dynamic content (timestamps, nonces, CSRF tokens, session IDs). Scores structural similarity, not byte equality. Used by BOLA/IDOR detectors to confirm that "attacker got victim's data" rather than "both got a differently-shaped 200 OK error page."

---

### 🗺️ OBJECT GRAPH · *The Map the Target Doesn't Know You're Drawing*

> `ObjectGraph`

Silently builds `URL → {resourceType, resourceId}` from every request Burp proxies. Zero extra requests. Zero performance cost. When an active BOLA check fires later, the graph already knows which object types exist, which IDs have been seen, and which endpoints serve which resources.

---

### ⏱️ TIMING UTILS · *The Clock That Lies — Until It Doesn't*

> `TimingUtils`

Statistical delay confirmation to prevent network jitter from becoming a false positive:

```
  1.  Measure baseline response time (N samples)
  2.  Send timed payload — measure response time
  3.  Re-send baseline — confirm network is stable
  4.  Flag anomaly ONLY if: (payload_time - baseline_mean) > k × baseline_stddev
```

`k` (sigma multiplier) and `N` (sample count) are tunable in Settings. Conservative defaults. Zero flukes.

---

### 🔍 RESPONSE DIFF · *The Shape of Truth*

> `ResponseDiff`

Token-aware structural diffing used by boolean-blind SQLi and all differential detectors. Ignores dynamic content. Scores *structural* changes. Makes boolean-blind detection reliable even on pages with high dynamic content — countdown timers, live feeds, CSRF tokens on every load.

---

### 🔒 CHAIN GUARD · *The Safety That Keeps the Hunter Honest*

> `ChainGuard`

Two safety controls over every multi-step chain detector:

**🟢 Safe Mode:** When enabled, skips any step marked `mutating=true`. Use this on pre-production environments where you don't want the extension actually submitting orders or applying discount codes during a scan. Chain detectors run their read-only verification steps only.

**📊 Request Budget:** Each chain has a maximum request count. Exceeding it aborts the chain and logs a warning — not an infinite loop on a complex workflow.

---

<br>

## 📜 05 · C U S T O M · R U L E · E N G I N E · — · 2 8 7 · R U L E S · O F · P O W E R

> `CustomRuleEngine` · `MiniJson` *(zero-dependency JSON parser — no external libs)*

Write custom passive or active checks in JSON. No Java. No rebuild. No restart.

Four professional rule packs ship inside the jar and **load automatically** every time the extension starts:

```
  ╔════════════════════════════════════════════════════════════════════╗
  ║   Pack                                           Rules   Focus    ║
  ╠════════════════════════════════════════════════════════════════════╣
  ║   01-p1-advanced-rules.json                        23    Web      ║
  ║   02-p1-mega-ruleset.json                         139    Mixed    ║
  ║   03-p1-web3-cloud-cms-webserver-rules.json        90    Modern   ║
  ║   04-p1-mobile-iot-mq-cicd-rules.json              35    Deep     ║
  ╠════════════════════════════════════════════════════════════════════╣
  ║   TOTAL                                           287             ║
  ╚════════════════════════════════════════════════════════════════════╝
```

### 📝 Rule Schema

```json
[
  {
    "name": "OS Command Injection - Error Signature",
    "type": "active",
    "severity": "high",
    "confidence": "firm",
    "description": "Shell metacharacter caused command execution output in response.",
    "remediation": "Never pass user input to a shell. Use parameterized APIs.",
    "conditions": [
      {
        "payload": ";id;",
        "match": "response_body",
        "pattern": "(?i)(uid=\\d+\\(.*?\\)|gid=\\d+\\(.*?\\))"
      }
    ]
  },
  {
    "name": "PEM Private Key in Response",
    "type": "passive",
    "severity": "critical",
    "confidence": "certain",
    "description": "A PEM-encoded private key was found in the HTTP response.",
    "conditions": [
      {
        "match": "response_body",
        "pattern": "-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"
      }
    ]
  }
]
```

**Rule types:**
- `"type": "passive"` — pattern-matches every response body/header. Zero extra requests.
- `"type": "active"` — injects `payload` at each insertion point, evaluates `match` against `response_body` · `response_headers` · `status`

### 🎛️ Rule Controls in the UI

| 🔘 Button | ⚡ Effect |
|:---|:---|
| **➕ Load from editor** | Adds your rules on top of bundled packs |
| **➕ Load from .json file** | Same — from a file on disk |
| **↻ Reload bundled rules** | Re-reads all four packs from the jar |
| **Clear manual rules** | Removes your rules only — bundled packs untouched |
| **Clear ALL rules** | Wipes everything — use Reload to restore |

> 💡 *To permanently add a 5th pack: drop your `.json` into `src/main/resources/rules/`, add its path to `BUNDLED_RULE_RESOURCES` in `CustomRuleEngine.java`, rebuild.*

---

<br>

## 🖥️ 06 · B U R P · U I · — · T H E · C O M M A N D · C E N T E R

A **"LawCyBug.pro"** tab appears in Burp's main UI the moment the extension loads. Three sub-tabs. One command center.

---

**📊 Dashboard** — Live findings table. Severity · Confidence · Detector · Host · Endpoint · Summary. Color-coded by severity. Click any row to see the full request/response evidence. Findings persist across Burp sessions — close Burp, reopen, your findings are still there.

**⚙️ Settings** — Per-detector toggles · Scan intensity · Timing sigma threshold · Sample count · Victim/Attacker identity management · Safe Mode toggle.

**📝 Rules Editor** — Live JSON editor. Load, reload, clear rules without restarting anything. Counter always shows: `Custom JSON Rules (287 bundled + N manual = X total)`

---

<br>

## 🔨 07 · B U I L D I N G · & · L O A D I N G · — · F O R G I N G · T H E · W E A P O N

### Prerequisites

```
  ☕  JDK 17+
  🔨  Apache Maven
  🌐  Internet access (to pull montoya-api:2026.4 from Maven Central — once)
```

### Build

```bash
# From the project root — 30 seconds on first run, 5 on subsequent
mvn clean package
```

```
  Output:  target/lawcybug-pro-scanner-1.0.0.jar
```

> 🔑 *The jar has zero runtime dependencies. Montoya API is `provided` scope — Burp supplies it at runtime. The JSON parser is hand-written (`MiniJson.java`). No fat-jar shading needed.*

### Load into Burp Suite

```
  Burp Suite  →  Extensions  →  Installed  →  Add
    Extension type:  Java
    Extension file:  target/lawcybug-pro-scanner-1.0.0.jar
```

On successful load, the Output tab prints:

```
  [LawCyBug.pro] Loading v1.0.0 ...
  [LawCyBug.pro] Bundled rules: 4/4 pack(s) loaded, 287 rule(s) total.
  [LawCyBug.pro] Loaded. Active detectors: 16  Passive detectors: 7
```

---

<br>

## ⚙️ 08 · S E T U P · & · C O N F I G U R A T I O N · — · A R M I N G · T H E · H U N T E R

### Basic Usage

Detectors run automatically inside Burp's normal scanner workflow:

- **Active scanning:** Right-click any request → *"Do active scan"*
- **Passive scanning:** All proxied traffic analyzed automatically — always on

Findings appear in the **LawCyBug.pro Dashboard** and Burp's native Issues / site map simultaneously.

---

### Setting Up IDOR / BOLA / Chain Detectors

These detectors need two authenticated sessions:

```
  1.  Log in to the target as Victim    (Account A) in Browser A
  2.  Log in to the target as Attacker  (Account B) in Browser B
  3.  Settings sub-tab → Identity Registry
      → Paste Attacker's session cookie or Authorization header value
  4.  Scan any Victim request
      → IDOR/BOLA detectors automatically replay it as Attacker
```

---

### SSRF / OOB Collaborator

```
  Project options → Misc → Burp Collaborator Server → configure
```

On Community Edition — OOB detectors silently stand down. No errors. No ghost findings.

---

### Safe Mode

Enable **Safe Mode** in Settings before scanning any environment where scan activity creates real-world side effects. Chain detectors will skip their mutating steps and run only read-only verification — no orders submitted, no coupons applied, no emails sent.

---

<br>

## 📁 09 · P R O J E C T · S T R U C T U R E · — · T H E · A N A T O M Y

```
  src/main/java/pro/lawcybug/scanner/
  │
  ├── 🔱 LawCyBugExtension.java              Entry point — wires everything together
  │
  ├── core/                                   The Engine Room
  │   ├── ActiveDetector.java                 Interface: audit(request, point, context)
  │   ├── PassiveDetector.java                Interface: passiveAudit(reqres, context)
  │   ├── DetectorEngine.java                 ScanCheck registered with Burp's scanner
  │   ├── DetectorContext.java                Shared wire: API · settings · store · collab
  │   ├── FindingsStore.java                  Thread-safe storage + session persistence
  │   ├── FindingsCorrelator.java             Chain detection across multiple findings
  │   ├── IssueFactory.java                   AuditIssue builder with evidence formatting
  │   ├── RequestFingerprintGuard.java        Deduplication — never scan the same point twice
  │   ├── ScanSettings.java                   All user-configurable settings
  │   └── Finding.java                        Finding value object
  │
  ├── detectors/                              The Hunters
  │   ├── sqli/
  │   │   ├── SqlErrorBasedDetector.java      🩸 Error-based SQLi
  │   │   ├── SqlBooleanBasedDetector.java    🟡 Boolean-blind — 3-way diff
  │   │   ├── SqlTimeBasedDetector.java       ⏱️  Time-based — statistical
  │   │   └── SqlPayloads.java                📚 Payload library
  │   ├── xss/
  │   │   └── ReflectedXssDetector.java       🎭 Two-phase context-aware XSS
  │   ├── cmdi/
  │   │   └── BlindCommandInjectionDetector   💻 Blind OS command injection
  │   ├── ssrf/
  │   │   ├── SsrfCollaboratorDetector.java   🌐 OOB SSRF via Collaborator
  │   │   └── SstiDetector.java               🧩 SSTI — 10 template engines
  │   ├── cors/
  │   │   └── CorsDetector.java               🌐 CORS — 4 attack classes
  │   ├── redirect/
  │   │   └── OpenRedirectDetector.java       🌍 Open redirect — all vectors
  │   ├── jwt/
  │   │   └── JwtMisconfigDetector.java       🔐 JWT — alg:none · empty sig
  │   ├── headers/
  │   │   └── SecurityHeadersDetector.java    🛡️  Security header audit
  │   ├── info/
  │   │   └── InfoDisclosureDetector.java     🕵️  Secrets + stack traces
  │   ├── idor/
  │   │   └── IdorAuthorizationDetector.java  🆔 IDOR cross-identity confirmation
  │   ├── bola/
  │   │   └── CrossIdentityBolaDetector.java  🗺️  Object-graph-driven BOLA
  │   ├── race/
  │   │   └── RaceConditionDetector.java      🏃 Barrier-burst race detection
  │   ├── massassignment/
  │   │   └── MassAssignmentConfirmDetector   📇 Mass assignment
  │   ├── authzbypass/
  │   │   └── AuthzBypassDetector.java        🔀 Authorization bypass
  │   ├── takeover/
  │   │   └── AccountTakeoverDetector.java    🔑 Account takeover vectors
  │   ├── atochain/
  │   │   └── PrivilegeEscalationChain...     👑 Two-step priv-esc chain
  │   ├── businesslogic/
  │   │   └── BusinessLogicAbuseDetector      🧮 Negative values + coupon reuse
  │   ├── graphql/
  │   │   └── GraphQlSecurityDetector.java    🕸️  GraphQL — 7 check types
  │   └── oauth/
  │       └── OAuthSecurityDetector.java      🔓 OAuth 2.0 / OIDC — 5 checks
  │
  ├── rules/
  │   ├── CustomRuleEngine.java               📜 JSON rule loader + evaluator
  │   └── MiniJson.java                       ⚡ Zero-dependency JSON parser
  │
  ├── workflow/
  │   ├── WorkflowEngine.java                 🔁 Multi-step HTTP chain execution
  │   ├── ChainGuard.java                     🔒 Safe Mode + request budget
  │   ├── IdentityRegistry.java               👥 Victim/attacker session store
  │   ├── SessionIdentity.java                🪪 Session header value object
  │   ├── ObjectGraph.java                    🗺️  Passive URL → resource map
  │   ├── ResponseSimilarityEngine.java       🧠 Structural response scoring
  │   └── JsonLite.java                       ⚡ Lightweight JSON extractor
  │
  ├── ui/
  │   └── LawCyBugTab.java                    🖥️  Dashboard · Settings · Rules
  │
  └── util/
      ├── TimingUtils.java                    ⏱️  Statistical timing confirmation
      ├── ResponseDiff.java                   🔍 Token-aware structural diff
      └── CanaryUtils.java                    🎯 Unique canary token generation

  src/main/resources/rules/
      ├── 01-p1-advanced-rules.json            23 rules
      ├── 02-p1-mega-ruleset.json             139 rules
      ├── 03-p1-web3-cloud-cms-webserver...    90 rules
      └── 04-p1-mobile-iot-mq-cicd-rules...   35 rules

  ════════════════════════════════════════════════════════
  ~3,500 lines of original Java  ·  28 source files  ·  287 bundled rules
  ════════════════════════════════════════════════════════
```

---

<br>

## ⚠️ 10 · E T H I C A L · U S E · — · T H E · C O D E

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║                                                                  ║
  ║   This extension is for AUTHORIZED security testing and          ║
  ║   LEGITIMATE bug bounty programs ONLY.                           ║
  ║                                                                  ║
  ║   The power of this tool is matched only by the responsibility   ║
  ║   of the person holding it.                                      ║
  ║                                                                  ║
  ╚══════════════════════════════════════════════════════════════════╝
```

- ✅ Only run against targets you have **explicit written permission** to test
- ✅ Always operate within the defined scope of your engagement or bug bounty program
- ✅ Enable **Safe Mode** on any environment where scan activity creates real-world side effects
- ✅ Confirm your engagement permits **OOB testing** before running SSRF/Collaborator checks
- ✅ Chain detectors that run mutating steps require explicit scope permission — they change real state

---

<br>

<div align="center">

```
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                                                                      ║
  ║        🕷️   LawCyBug.pro  ·  v0.2.0-tier1   🕷️                     ║
  ║                                                                      ║
  ║    16 active detectors  ·  7 passive watchers  ·  287 rules         ║
  ║    ~3,500 lines of Java  ·  28 files  ·  0 dependencies             ║
  ║                                                                      ║
  ║         Built with 🖤 for hunters who need to be right.             ║
  ║                                                                      ║
  ╚══════════════════════════════════════════════════════════════════════╝
```

*"Others scan. You hunt."*

</div>
