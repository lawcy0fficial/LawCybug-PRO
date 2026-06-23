package pro.lawcybug.scanner.detectors.xss;

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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reflected XSS detector built around a two-phase approach to keep
 * accuracy high:
 *
 *   Phase 1 (context probe): reflect a unique alphanumeric canary with
 *   no special characters, to find out WHERE and IN WHAT CONTEXT
 *   (raw HTML body, HTML attribute, <script> block, HTML comment)
 *   the input lands, without yet triggering any WAF/filter.
 *
 *   Phase 2 (context-specific payload): only then send a payload
 *   shaped for that exact context (e.g. attribute-breakout vs
 *   tag-breakout vs script-context), and confirm the dangerous
 *   characters survive UNENCODED in the response.
 *
 * This two-phase approach is what separates "grep for <script>" naive
 * scanners (high false-positive AND false-negative rate) from a
 * context-aware one.
 */
public final class ReflectedXssDetector implements ActiveDetector {

    public static final String ID = "xss.reflected";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Cross-Site Scripting - Reflected (context-aware)";
    }

    @Override
    public String description() {
        return "Probes reflection context first, then sends a context-specific payload and verifies it survives unencoded.";
    }

    @Override
    public String category() {
        return "Client-Side";
    }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        String canary = CanaryUtils.randomToken();

        HttpRequestResponse probeResult = ctx.api().http().sendRequest(
                insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(canary)));
        if (probeResult.response() == null) {
            return issues;
        }
        String probeBody = probeResult.response().bodyToString();
        int reflectionIndex = probeBody.indexOf(canary);
        if (reflectionIndex < 0) {
            return issues; // not reflected at all, nothing more to do here
        }

        ReflectionContext context = classify(probeBody, reflectionIndex, canary.length());
        String payload = context.buildPayload(canary);

        HttpRequestResponse confirmResult = ctx.api().http().sendRequest(
                insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload)));
        if (confirmResult.response() == null) {
            return issues;
        }
        String confirmBody = confirmResult.response().bodyToString();

        // The payload must appear VERBATIM (unencoded) for this to be exploitable.
        int payloadIndex = confirmBody.indexOf(payload);
        if (payloadIndex < 0) {
            return issues;
        }

        // Sanity-check content type isn't something where script wouldn't
        // execute anyway (e.g. JSON API responses, plain text downloads).
        String contentType = headerValue(confirmResult, "Content-Type");
        boolean htmlLike = contentType == null || contentType.toLowerCase().contains("html")
                || contentType.toLowerCase().contains("xml") || contentType.isEmpty();
        AuditIssueConfidence confidence = htmlLike ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE;

        HttpRequestResponse highlighted = IssueFactory.withResponseBodyHighlight(
                confirmResult, payloadIndex, payloadIndex + payload.length());

        String detail =
                IssueFactory.evidenceParagraph("Insertion point", insertionPoint.name())
                        + IssueFactory.evidenceParagraph("Reflection context", context.label)
                        + IssueFactory.evidenceParagraph("Confirmation payload", payload)
                        + IssueFactory.evidenceParagraph("Response Content-Type", String.valueOf(contentType));

        issues.add(IssueFactory.build(
                "Cross-Site Scripting (Reflected)",
                detail,
                "Context-appropriate output encoding is required: HTML-entity encode for HTML body "
                        + "context, attribute-encode and quote all attributes for attribute context, and "
                        + "avoid reflecting user input inside &lt;script&gt; blocks entirely. Adopt a strict "
                        + "Content-Security-Policy as defense in depth.",
                base.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                "A unique canary value was reflected in the response, and a payload shaped for the "
                        + "observed reflection context (" + context.label + ") survived in the response "
                        + "completely unencoded, indicating the application does not sanitize or encode "
                        + "this input before rendering it.",
                highlighted
        ));

        return issues;
    }

    private String headerValue(HttpRequestResponse rr, String name) {
        return rr.response().headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(h -> h.value())
                .findFirst().orElse(null);
    }

    private ReflectionContext classify(String body, int index, int canaryLength) {
        // Walk backwards from the reflection point to figure out context.
        int windowStart = Math.max(0, index - 200);
        String before = body.substring(windowStart, index);

        // Inside a <script> ... block?
        int lastScriptOpen = before.toLowerCase().lastIndexOf("<script");
        int lastScriptClose = before.toLowerCase().lastIndexOf("</script");
        if (lastScriptOpen > lastScriptClose) {
            return ReflectionContext.SCRIPT;
        }

        // Inside an HTML comment?
        int lastCommentOpen = before.lastIndexOf("<!--");
        int lastCommentClose = before.lastIndexOf("-->");
        if (lastCommentOpen > lastCommentClose) {
            return ReflectionContext.HTML_COMMENT;
        }

        // Inside an attribute value? Look for an unclosed quote after the
        // last '<' before our reflection point.
        int lastTagOpen = before.lastIndexOf('<');
        if (lastTagOpen >= 0) {
            String tagFragment = before.substring(lastTagOpen);
            // crude but effective: odd number of " or ' means we're inside one
            long dq = tagFragment.chars().filter(c -> c == '"').count();
            long sq = tagFragment.chars().filter(c -> c == '\'').count();
            boolean tagNotClosed = !tagFragment.contains(">");
            if (tagNotClosed && dq % 2 == 1) {
                return ReflectionContext.DOUBLE_QUOTED_ATTRIBUTE;
            }
            if (tagNotClosed && sq % 2 == 1) {
                return ReflectionContext.SINGLE_QUOTED_ATTRIBUTE;
            }
            if (tagNotClosed) {
                return ReflectionContext.UNQUOTED_ATTRIBUTE;
            }
        }

        return ReflectionContext.HTML_BODY;
    }

    private enum ReflectionContext {
        HTML_BODY("Raw HTML body") {
            String buildPayload(String canary) {
                return "<lcb" + canary + " onmouseover=alert(1)>X</lcb" + canary + ">";
            }
        },
        DOUBLE_QUOTED_ATTRIBUTE("Double-quoted HTML attribute") {
            String buildPayload(String canary) {
                return "\" onmouseover=\"alert('" + canary + "')\" lcb=\"";
            }
        },
        SINGLE_QUOTED_ATTRIBUTE("Single-quoted HTML attribute") {
            String buildPayload(String canary) {
                return "' onmouseover='alert(" + canary + ")' lcb='";
            }
        },
        UNQUOTED_ATTRIBUTE("Unquoted HTML attribute") {
            String buildPayload(String canary) {
                return " onmouseover=alert(" + canary + ") lcb=";
            }
        },
        SCRIPT("Inline <script> block") {
            String buildPayload(String canary) {
                return "';alert('" + canary + "');//";
            }
        },
        HTML_COMMENT("Inside an HTML comment") {
            String buildPayload(String canary) {
                return "--><script>alert('" + canary + "')</script><!--";
            }
        };

        final String label;

        ReflectionContext(String label) {
            this.label = label;
        }

        abstract String buildPayload(String canary);
    }
}
