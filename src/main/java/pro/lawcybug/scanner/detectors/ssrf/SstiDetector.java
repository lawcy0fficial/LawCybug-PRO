package pro.lawcybug.scanner.detectors.ssrf;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
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

/**
 * Server-Side Template Injection (SSTI) detector.
 * Uses arithmetic confirmation: inject {canary*canary} or equivalent,
 * then check the response for the known-correct product. This avoids
 * the massive false-positive rate of grepping for {{ or #{ alone.
 */
public final class SstiDetector implements ActiveDetector {

    public static final String ID = "ssti.arithmetic";

    // Table of {payload format, template engine label, multiplier result check}
    // Each entry: String[3] = { probeFormat, engineLabel, resultToLookFor }
    // probeFormat uses %d for the number, and the product is %d^2.
    private static final int CANARY_NUM = 7639;      // chosen to be unlikely to appear naturally
    private static final String EXPECTED = String.valueOf(CANARY_NUM * CANARY_NUM);

    // Each entry: {payload string (with %d substituted), engine label}
    private static final List<String[]> PROBES = List.of(
            new String[]{"{{" + CANARY_NUM + "*" + CANARY_NUM + "}}", "Jinja2/Twig"},
            new String[]{"${" + CANARY_NUM + "*" + CANARY_NUM + "}", "Freemarker/Spring EL"},
            new String[]{"<%= " + CANARY_NUM + "*" + CANARY_NUM + " %>", "ERB (Ruby)"},
            new String[]{"#{" + CANARY_NUM + "*" + CANARY_NUM + "}", "Ruby"},
            new String[]{"@(" + CANARY_NUM + "*" + CANARY_NUM + ")", "Razor (.NET)"},
            new String[]{"${{" + CANARY_NUM + "*" + CANARY_NUM + "}}", "Jinja2 (alt)"},
            new String[]{"*{" + CANARY_NUM + "*" + CANARY_NUM + "}", "Thymeleaf Spring"},
            new String[]{"{{=" + CANARY_NUM + "*" + CANARY_NUM + "}}", "Pebble"},
            new String[]{"`" + CANARY_NUM + "*" + CANARY_NUM + "`", "Mako/Python"},
            new String[]{"{{" + CANARY_NUM + "|int*" + CANARY_NUM + "|int}}", "Jinja2 filter-based"}
    );

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Server-Side Template Injection (SSTI)"; }
    @Override public String description() { return "Arithmetic confirmation probes across Jinja2, Twig, Freemarker, ERB, Razor, Thymeleaf and more."; }
    @Override public String category()    { return "Injection"; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        for (String[] probe : PROBES) {
            String payload = probe[0];
            String engine  = probe[1];

            HttpRequestResponse result = ctx.api().http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload)));
            if (result.response() == null) continue;

            String body = result.response().bodyToString();
            int idx = body.indexOf(EXPECTED);
            if (idx >= 0) {
                HttpRequestResponse highlighted = IssueFactory.withResponseBodyHighlight(result, idx, idx + EXPECTED.length());
                String detail =
                        IssueFactory.evidenceParagraph("Insertion point", insertionPoint.name())
                                + IssueFactory.evidenceParagraph("Payload", payload)
                                + IssueFactory.evidenceParagraph("Engine suspected", engine)
                                + IssueFactory.evidenceParagraph("Arithmetic result in response", EXPECTED);

                issues.add(IssueFactory.build(
                        "Server-Side Template Injection (SSTI) - " + engine,
                        detail,
                        "Never pass user-controlled input directly to a template engine. Pass values "
                                + "as context variables into a static template string, never concatenate "
                                + "user data as the template source itself.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "The arithmetic expression " + CANARY_NUM + "*" + CANARY_NUM
                                + " was submitted inside a template syntax probe and the server "
                                + "returned its correct product (" + EXPECTED + ") in the response "
                                + "body, proving the template engine evaluated our input as code.",
                        highlighted));
                break; // one engine confirmed per insertion point is sufficient
            }
        }
        return issues;
    }
}
