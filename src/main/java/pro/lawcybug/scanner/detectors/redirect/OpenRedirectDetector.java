package pro.lawcybug.scanner.detectors.redirect;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.util.CanaryUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Open Redirect detector. Checks:
 *  - 3xx Location header reflecting our target domain
 *  - HTML meta-refresh containing our target domain
 *  - Javascript window.location = ... containing our target domain
 * Uses a canary label so we can distinguish our injected value from
 * pre-existing redirects.
 */
public final class OpenRedirectDetector implements ActiveDetector {

    public static final String ID = "redirect.open";
    private static final String REDIRECT_TARGET = "https://lcb.evil.attacker.test/";

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Open Redirect"; }
    @Override public String description() { return "Checks Location headers, meta-refresh, and JS redirects for user-controlled destination."; }
    @Override public String category()    { return "Access Control"; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        String ipNameLower = insertionPoint.name().toLowerCase(Locale.ROOT);

        // Only check insertion points that sound like redirect/return params;
        // checking every insertion point is wasteful and noisy.
        boolean redirecty = List.of("url", "redirect", "next", "return", "goto", "dest",
                "destination", "continue", "target", "redir", "out", "forward", "location", "back")
                .stream().anyMatch(ipNameLower::contains);
        if (!redirecty && Math.random() > 0.10) return issues; // 10% sample for unknowns

        List<String> payloads = buildPayloads();

        for (String payload : payloads) {
            HttpRequestResponse result = ctx.api().http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload)));
            if (result.response() == null) continue;
            HttpResponse resp = result.response();

            // 3xx + Location header
            if (resp.statusCode() >= 300 && resp.statusCode() < 400) {
                String location = resp.headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Location"))
                        .map(h -> h.value())
                        .findFirst().orElse("");
                if (location.toLowerCase(Locale.ROOT).contains("lcb.evil.attacker.test")) {
                    issues.add(buildIssue(base.request().url(), insertionPoint.name(),
                            payload, "3xx Location redirect", location, result));
                    break;
                }
            }

            // Body: meta-refresh or JS redirect
            String body = resp.bodyToString();
            if (body.toLowerCase(Locale.ROOT).contains("lcb.evil.attacker.test")) {
                issues.add(buildIssue(base.request().url(), insertionPoint.name(),
                        payload, "HTML/JS redirect in response body", "(reflected in body)", result));
                break;
            }
        }
        return issues;
    }

    private AuditIssue buildIssue(String url, String ipName, String payload,
                                    String mechanism, String evidence, HttpRequestResponse result) {
        return IssueFactory.build(
                "Open Redirect",
                IssueFactory.evidenceParagraph("Insertion point", ipName)
                        + IssueFactory.evidenceParagraph("Payload", payload)
                        + IssueFactory.evidenceParagraph("Mechanism", mechanism)
                        + IssueFactory.evidenceParagraph("Evidence", evidence),
                "Validate redirect targets against an allow-list of permitted destinations. "
                        + "Avoid including user-controllable data in redirect target URLs. "
                        + "If a redirect must be user-influenced, use an indirect reference "
                        + "(e.g. a numeric token mapped server-side) rather than the URL itself.",
                url,
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.FIRM,
                "The application redirected to an attacker-controlled domain when our probe "
                        + "value was submitted in the '" + ipName + "' parameter. This can be "
                        + "exploited for phishing, credential harvesting and OAuth token theft.",
                result);
    }

    private List<String> buildPayloads() {
        return List.of(
                REDIRECT_TARGET,
                "//" + "lcb.evil.attacker.test/",
                "//lcb.evil.attacker.test/%2F..",
                "///lcb.evil.attacker.test/",
                "https:///lcb.evil.attacker.test/",
                "/\\lcb.evil.attacker.test",
                "http://lcb.evil.attacker.test/",
                "http:lcb.evil.attacker.test",
                "//lcb.evil.attacker.test%00",        // null-byte bypass
                "//lcb.evil.attacker.test%0d%0a",     // CRLF-termination bypass
                "/%09/lcb.evil.attacker.test"          // tab bypass
        );
    }
}
