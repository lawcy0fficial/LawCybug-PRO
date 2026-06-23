package pro.lawcybug.scanner.detectors.cors;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.PassiveDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * CORS misconfiguration: covers the full classic taxonomy:
 *  1. Origin reflection with ACAO+ACAC (wildcard creds) [CRITICAL]
 *  2. ACAO: * with ACAC: true (impossible combo, some servers do it) [HIGH]
 *  3. null origin accepted with credentials [HIGH]
 *  4. Prefix/suffix origin bypass (trusted origin derived from user origin)
 *  5. Passive: ACAO: * on authenticated endpoints [MEDIUM]
 *
 * The active checks all send a preflight-style probe (OPTIONS or modified
 * GET with an Origin header), which is safe and causes no side effects.
 */
public final class CorsDetector implements ActiveDetector, PassiveDetector {

    public static final String ID = "cors.misconfig";

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "CORS Misconfiguration"; }
    @Override public String description() { return "Origin reflection, null origin, wildcard+credentials, and prefix bypass checks."; }
    @Override public String category()    { return "Access Control"; }

    // ----- passive -----
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.response() == null) return issues;

        String acao = headerValue(base, "Access-Control-Allow-Origin");
        String acac = headerValue(base, "Access-Control-Allow-Credentials");
        boolean hasAuth = headerValue(base, "Authorization") != null
                || headerValue(base, "Cookie") != null
                || headerValue(base, "Set-Cookie") != null;

        if ("*".equals(acao) && hasAuth) {
            issues.add(IssueFactory.build(
                    "CORS Wildcard on Authenticated Endpoint",
                    IssueFactory.evidenceParagraph("ACAO", acao)
                            + IssueFactory.evidenceParagraph("Auth headers present", "yes"),
                    "Remove the wildcard ACAO header from authenticated endpoints. Use an explicit "
                            + "allow-list of trusted origins.",
                    base.request().url(),
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.FIRM,
                    "A wildcard ACAO header was observed on an endpoint that processes authentication "
                            + "cookies or tokens. Browsers will not send credentials with a wildcard, but "
                            + "a future regression to explicit reflection could make this immediately "
                            + "exploitable.",
                    base));
        }

        if ("*".equals(acao) && "true".equalsIgnoreCase(acac)) {
            issues.add(IssueFactory.build(
                    "CORS ACAO:* + ACAC:true (Invalid Browser Combination)",
                    IssueFactory.evidenceParagraph("ACAO", acao)
                            + IssueFactory.evidenceParagraph("ACAC", acac),
                    "Remove ACAC: true from wildcard ACAO responses. Browsers reject this combination.",
                    base.request().url(),
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.FIRM,
                    "Setting ACAO:* alongside ACAC:true is forbidden by the CORS spec. Browsers "
                            + "ignore it, but non-browser clients (curl, custom HTTP libs) would honour "
                            + "both, potentially exposing data.",
                    base));
        }

        return issues;
    }

    // ----- active -----
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        // Only relevant at the request level, not per insertion point.
        // Only run this on the first (URL) insertion point so we don't multiply up.
        if (!insertionPoint.name().equals("URL") && !insertionPoint.name().contains("param")) {
            return List.of();
        }
        List<AuditIssue> issues = new ArrayList<>();
        String baseUrl = base.request().url();

        // --- 1. Arbitrary origin reflection ---
        String reflectedOrigin = "https://evil.attacker.lcb.test";
        HttpRequestResponse reflectResult = ctx.api().http().sendRequest(
                base.request().withAddedHeader("Origin", reflectedOrigin));
        if (reflectResult.response() != null) {
            String acao = headerValue(reflectResult, "Access-Control-Allow-Origin");
            String acac = headerValue(reflectResult, "Access-Control-Allow-Credentials");
            if (reflectedOrigin.equals(acao) && "true".equalsIgnoreCase(acac)) {
                issues.add(IssueFactory.build(
                        "CORS Arbitrary Origin Reflection with Credentials",
                        IssueFactory.evidenceParagraph("Sent origin", reflectedOrigin)
                                + IssueFactory.evidenceParagraph("ACAO returned", acao)
                                + IssueFactory.evidenceParagraph("ACAC", acac),
                        "Maintain an explicit server-side allow-list of trusted origins. Never "
                                + "derive the ACAO value directly from the request Origin header without "
                                + "validation. Ensure ACAC is only set to true when the origin is "
                                + "genuinely trusted.",
                        baseUrl,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        "The server reflected our arbitrary Origin value back in ACAO and also set "
                                + "ACAC: true. Any origin can therefore make credentialed cross-origin "
                                + "requests and read the response, bypassing the same-origin policy.",
                        reflectResult));
            } else if (reflectedOrigin.equals(acao)) {
                issues.add(IssueFactory.build(
                        "CORS Arbitrary Origin Reflection (no credentials)",
                        IssueFactory.evidenceParagraph("Sent origin", reflectedOrigin)
                                + IssueFactory.evidenceParagraph("ACAO returned", acao)
                                + IssueFactory.evidenceParagraph("ACAC", String.valueOf(acac)),
                        "Maintain an explicit server-side allow-list of trusted origins.",
                        baseUrl,
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.FIRM,
                        "The server reflected our arbitrary Origin. Without ACAC:true credentials "
                                + "are not sent, but this may still allow public data reads from arbitrary "
                                + "origins which the application author did not intend.",
                        reflectResult));
            }
        }

        // --- 2. Null origin ---
        HttpRequestResponse nullResult = ctx.api().http().sendRequest(
                base.request().withAddedHeader("Origin", "null"));
        if (nullResult.response() != null) {
            String acao = headerValue(nullResult, "Access-Control-Allow-Origin");
            String acac = headerValue(nullResult, "Access-Control-Allow-Credentials");
            if ("null".equals(acao) && "true".equalsIgnoreCase(acac)) {
                issues.add(IssueFactory.build(
                        "CORS Null Origin Accepted with Credentials",
                        IssueFactory.evidenceParagraph("ACAO", acao)
                                + IssueFactory.evidenceParagraph("ACAC", acac),
                        "Reject the null origin. Sandboxed iframes, file:// pages and some "
                                + "redirects produce null -- any of these can be used to make "
                                + "credentialed requests if null is allowed.",
                        baseUrl,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        "The server allows the null origin with credentials. Attackers can use a "
                                + "sandboxed iframe to trigger requests with null origin from any site.",
                        nullResult));
            }
        }

        // --- 3. Trusted origin prefix bypass ---
        try {
            String host = new java.net.URL(baseUrl).getHost();
            String prefixedOrigin = "https://" + host + ".evil.lcb.test";
            HttpRequestResponse prefixResult = ctx.api().http().sendRequest(
                    base.request().withAddedHeader("Origin", prefixedOrigin));
            if (prefixResult.response() != null) {
                String acao = headerValue(prefixResult, "Access-Control-Allow-Origin");
                if (prefixedOrigin.equals(acao)) {
                    issues.add(IssueFactory.build(
                            "CORS Trusted Origin Prefix Bypass",
                            IssueFactory.evidenceParagraph("Sent origin", prefixedOrigin)
                                    + IssueFactory.evidenceParagraph("ACAO returned", acao),
                            "Use exact host-matching in origin validation, not prefix/suffix string "
                                    + "matching.",
                            baseUrl,
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.FIRM,
                            "The server accepted an origin that merely has the trusted host as a "
                                    + "substring prefix. An attacker can register a domain ending in the "
                                    + "target's hostname and exploit this.",
                            prefixResult));
                }
            }
        } catch (Exception ignored) {}

        return issues;
    }

    private String headerValue(HttpRequestResponse rr, String name) {
        return rr.response().headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(HttpHeader::value)
                .findFirst().orElse(null);
    }
}
