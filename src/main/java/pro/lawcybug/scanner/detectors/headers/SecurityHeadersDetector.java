package pro.lawcybug.scanner.detectors.headers;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.PassiveDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Passive checks for missing or dangerously misconfigured security-
 * related HTTP response headers (2025/2026 best-practice baseline).
 * Each check is independent so disabling one doesn't silence the rest.
 */
public final class SecurityHeadersDetector implements PassiveDetector {

    public static final String ID = "headers.security";

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Missing / Misconfigured Security Headers"; }
    @Override public String description() { return "Passive checks for CSP, HSTS, X-Frame-Options, Referrer-Policy, CORP/COEP and more."; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.response() == null) return issues;

        HttpResponse resp = base.response();
        String url = base.request().url();
        String contentType = header(resp, "Content-Type");
        boolean isHtml = contentType != null && contentType.toLowerCase(Locale.ROOT).contains("text/html");
        boolean isHttps = url.startsWith("https://");

        // ── 1. Content-Security-Policy ──────────────────────────────────────
        String csp = header(resp, "Content-Security-Policy");
        if (isHtml && csp == null) {
            issues.add(IssueFactory.build(
                    "Missing Content-Security-Policy Header",
                    "<p>No <code>Content-Security-Policy</code> response header was returned for this HTML response.</p>",
                    "Deploy a Content-Security-Policy header with at minimum <code>default-src 'self'</code>. "
                            + "Gradually tighten to remove 'unsafe-inline' and 'unsafe-eval'. "
                            + "Use CSP nonces or hashes for inline scripts.",
                    url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN,
                    "The absence of a Content-Security-Policy header means the browser will not "
                            + "enforce any restrictions on which scripts, styles or media the page may "
                            + "load, leaving XSS payloads free to execute.",
                    base));
        } else if (csp != null) {
            // Audit the CSP value for known weaknesses
            String cspLower = csp.toLowerCase(Locale.ROOT);
            if (cspLower.contains("'unsafe-eval'")) {
                issues.add(IssueFactory.build(
                        "Content-Security-Policy Allows unsafe-eval",
                        IssueFactory.evidenceParagraph("CSP", csp),
                        "Remove 'unsafe-eval' from the CSP. Refactor code that relies on eval(), "
                                + "setTimeout(string), setInterval(string) and Function() constructor.",
                        url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN,
                        "'unsafe-eval' permits dynamic code execution which can be used by attackers "
                                + "to execute injected script content.", base));
            }
            if (cspLower.contains("'unsafe-inline'") && !cspLower.contains("nonce-") && !cspLower.contains("hash-")) {
                issues.add(IssueFactory.build(
                        "Content-Security-Policy Allows unsafe-inline Without Nonce/Hash",
                        IssueFactory.evidenceParagraph("CSP", csp),
                        "Replace 'unsafe-inline' with script nonces or hashes to allow only specific inline scripts.",
                        url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN,
                        "'unsafe-inline' allows execution of any inline script, significantly "
                                + "reducing CSP's protection against XSS.", base));
            }
            if (cspLower.contains("*") && !cspLower.contains("'none'")) {
                issues.add(IssueFactory.build(
                        "Content-Security-Policy Contains Wildcard Source",
                        IssueFactory.evidenceParagraph("CSP", csp),
                        "Replace wildcard source directives with specific trusted domains.",
                        url, AuditIssueSeverity.LOW, AuditIssueConfidence.FIRM,
                        "A wildcard source in CSP allows scripts/frames to be loaded from any origin.", base));
            }
        }

        // ── 2. Strict-Transport-Security ────────────────────────────────────
        if (isHttps) {
            String hsts = header(resp, "Strict-Transport-Security");
            if (hsts == null) {
                issues.add(IssueFactory.build(
                        "Missing Strict-Transport-Security (HSTS) Header",
                        "<p>No HSTS header was present on this HTTPS response.</p>",
                        "Add <code>Strict-Transport-Security: max-age=63072000; includeSubDomains; preload</code>.",
                        url, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN,
                        "Without HSTS a user who visits the HTTP version of the site can be "
                                + "SSL-stripped. HSTS forces the browser to use HTTPS for all future "
                                + "visits within the max-age window.", base));
            } else {
                // Check max-age adequacy
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("max-age=([0-9]+)", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(hsts);
                if (m.find()) {
                    long maxAge = Long.parseLong(m.group(1));
                    if (maxAge < 31536000) {
                        issues.add(IssueFactory.build(
                                "HSTS max-age Too Short",
                                IssueFactory.evidenceParagraph("HSTS", hsts)
                                        + IssueFactory.evidenceParagraph("max-age (seconds)", String.valueOf(maxAge)),
                                "Set max-age to at least 31536000 (1 year). The HSTS preload list "
                                        + "requires at least 31536000 with includeSubDomains.",
                                url, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN,
                                "An HSTS max-age below one year provides only brief protection. "
                                        + "A user who has not visited within that window reverts to "
                                        + "HTTP-strippable behaviour.", base));
                    }
                }
            }
        }

        // ── 3. X-Frame-Options / frame-ancestors ────────────────────────────
        if (isHtml) {
            String xfo = header(resp, "X-Frame-Options");
            boolean frameAncestorsInCsp = csp != null && csp.toLowerCase(Locale.ROOT).contains("frame-ancestors");
            if (xfo == null && !frameAncestorsInCsp) {
                issues.add(IssueFactory.build(
                        "Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)",
                        "<p>Neither <code>X-Frame-Options</code> nor a CSP <code>frame-ancestors</code> directive was found.</p>",
                        "Add <code>Content-Security-Policy: frame-ancestors 'none'</code> (or 'self' "
                                + "if embedding is required). X-Frame-Options is a legacy alternative "
                                + "for older browsers.",
                        url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN,
                        "Without framing controls this page can be embedded in an attacker's iframe "
                                + "for clickjacking attacks.", base));
            }
        }

        // ── 4. X-Content-Type-Options ────────────────────────────────────────
        String xcto = header(resp, "X-Content-Type-Options");
        if (xcto == null) {
            issues.add(IssueFactory.build(
                    "Missing X-Content-Type-Options Header",
                    "<p>No <code>X-Content-Type-Options: nosniff</code> header was returned.</p>",
                    "Add <code>X-Content-Type-Options: nosniff</code> to all responses.",
                    url, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN,
                    "Without nosniff, older browsers may MIME-sniff a response and execute it "
                            + "as a different content type than declared (e.g., execute text/plain as script).", base));
        }

        // ── 5. Referrer-Policy ───────────────────────────────────────────────
        String rp = header(resp, "Referrer-Policy");
        if (rp == null) {
            issues.add(IssueFactory.build(
                    "Missing Referrer-Policy Header",
                    "<p>No <code>Referrer-Policy</code> header was set.</p>",
                    "Set <code>Referrer-Policy: strict-origin-when-cross-origin</code> at minimum.",
                    url, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN,
                    "Without Referrer-Policy the browser may send the full URL (including "
                            + "parameters, tokens, path) in the Referer header to third-party origins.", base));
        }

        // ── 6. Permissions-Policy ────────────────────────────────────────────
        String pp = header(resp, "Permissions-Policy");
        if (isHtml && pp == null) {
            issues.add(IssueFactory.build(
                    "Missing Permissions-Policy Header",
                    "<p>No <code>Permissions-Policy</code> response header was found.</p>",
                    "Define a Permissions-Policy restricting unused powerful features: "
                            + "e.g. <code>Permissions-Policy: camera=(), microphone=(), geolocation=()</code>.",
                    url, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN,
                    "Without Permissions-Policy the page and any embedded third-party content may "
                            + "request camera, microphone, geolocation and other sensitive browser "
                            + "capabilities without restriction.", base));
        }

        // ── 7. Server header version disclosure ─────────────────────────────
        String serverHeader = header(resp, "Server");
        if (serverHeader != null && serverHeader.matches(".*[0-9]+\\.[0-9]+.*")) {
            issues.add(IssueFactory.build(
                    "Server Version Disclosure via Server Header",
                    IssueFactory.evidenceParagraph("Server", serverHeader),
                    "Configure the web server to suppress or genericize the Server header value.",
                    url, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN,
                    "Disclosing the exact server software version allows attackers to identify "
                            + "known CVEs affecting that version.", base));
        }

        // ── 8. X-Powered-By ─────────────────────────────────────────────────
        String xpb = header(resp, "X-Powered-By");
        if (xpb != null) {
            issues.add(IssueFactory.build(
                    "Technology Disclosure via X-Powered-By Header",
                    IssueFactory.evidenceParagraph("X-Powered-By", xpb),
                    "Remove the X-Powered-By header in your framework/server configuration.",
                    url, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN,
                    "X-Powered-By discloses the server-side technology stack to attackers.", base));
        }

        return issues;
    }

    private String header(HttpResponse resp, String name) {
        return resp.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(h -> h.value())
                .findFirst().orElse(null);
    }
}
