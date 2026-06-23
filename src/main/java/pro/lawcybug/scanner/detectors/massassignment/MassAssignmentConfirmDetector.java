package pro.lawcybug.scanner.detectors.massassignment;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.RequestFingerprintGuard;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Mass Assignment CONFIRMATION detector.
 *
 * The JSON rule engine can only check "did the privileged field get
 * echoed back in THIS response" -- which produces false positives any
 * time an API defensively echoes the full request body back regardless
 * of whether it actually bound the field to the persistence model. This
 * detector confirms real impact with a two-step sequence:
 *
 *   Step 1 (write): take the base write request (POST/PUT/PATCH) and
 *           inject one of several privileged-field candidates into the
 *           JSON body (role/isAdmin/is_admin/admin/permissions/verified/
 *           balance/price/discount) with an attacker-favorable value,
 *           using a marker value we control so we can recognize it
 *           unambiguously later.
 *   Step 2 (read-back): immediately re-request the SAME resource with a
 *           plain GET (derived from the write request's URL/path -- most
 *           REST APIs expose GET on the same collection/resource path)
 *           using the ORIGINAL (unmodified) request's credentials, and
 *           check whether our marker value is now present in a FRESH read
 *           -- i.e. it was actually persisted server-side, not just
 *           reflected in the write response.
 *
 * Only firing when the read-back independently confirms persistence
 * avoids the most common false-positive source for this bug class.
 */
public final class MassAssignmentConfirmDetector implements ActiveDetector {

    public static final String ID = "logic.mass_assignment.confirm";

    private static final String MARKER = "lwcb7331";

    private static final List<String[]> CANDIDATE_FIELDS = List.of(
            new String[]{"role", "\"admin_" + MARKER + "\""},
            new String[]{"isAdmin", "true"},
            new String[]{"is_admin", "true"},
            new String[]{"admin", "true"},
            new String[]{"verified", "true"},
            new String[]{"is_verified", "true"},
            new String[]{"permissions", "[\"*_" + MARKER + "\"]"},
            new String[]{"price", "0.01"},
            new String[]{"balance", "999999"},
            new String[]{"discount_percent", "100"}
    );

    private static final Pattern JSON_BODY_HINT = Pattern.compile("^\\s*[\\{\\[]");

    // This detector ignores the insertion point entirely -- it mutates
    // the WHOLE JSON body and fires write+read-back requests. Without
    // this guard, a request with N JSON fields (= N insertion points)
    // would repeat every candidate-field write N times, multiplying real
    // side-effecting writes against the target for zero added coverage.
    private final RequestFingerprintGuard guard = new RequestFingerprintGuard();

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Mass Assignment Confirmation (Inject + Read-Back Verify)"; }
    @Override public String description() { return "Injects privileged JSON fields into write requests and confirms persistence via an independent authenticated read."; }
    @Override public String category()    { return "Business Logic"; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.request() == null) return issues;

        String method = base.request().method();
        boolean isWrite = method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")
                || method.equalsIgnoreCase("PATCH");
        if (!isWrite) return issues;

        String body = base.request().bodyToString();
        if (body == null || !JSON_BODY_HINT.matcher(body).find()) {
            return issues; // only handles JSON-bodied write requests
        }

        if (!guard.claim(base)) {
            return issues; // already tried the full candidate-field battery for this exact request very recently
        }

        for (String[] candidate : CANDIDATE_FIELDS) {
            String fieldName = candidate[0];
            String injectedValue = candidate[1];

            // Skip fields that are already legitimately present with the
            // exact same value -- nothing to confirm there.
            if (body.contains("\"" + fieldName + "\"") && body.contains(injectedValue)) continue;

            String mutatedBody = injectField(body, fieldName, injectedValue);
            if (mutatedBody.equals(body)) continue;

            HttpRequest writeReq = base.request().withBody(ByteArray.byteArray(mutatedBody));
            HttpRequestResponse writeResult = ctx.api().http().sendRequest(writeReq);
            if (writeResult.response() == null) continue;

            int writeStatus = writeResult.response().statusCode();
            if (writeStatus < 200 || writeStatus >= 300) continue; // server rejected the write outright

            // Step 2: independent read-back using the ORIGINAL request's
            // method swapped to GET against the same URL, same auth headers.
            HttpRequest readReq = writeReq.withMethod("GET").withBody(ByteArray.byteArray(""));
            HttpRequestResponse readResult = ctx.api().http().sendRequest(readReq);
            if (readResult.response() == null) continue;

            String readBody = readResult.response().bodyToString();
            boolean persisted = readBody != null && (readBody.contains(MARKER) || valueActuallyPersisted(readBody, fieldName, injectedValue));

            if (persisted) {
                issues.add(IssueFactory.build(
                        "Mass Assignment Confirmed - Privileged Field '" + fieldName + "' Persisted",
                        IssueFactory.evidenceParagraph("Injected field", fieldName)
                                + IssueFactory.evidenceParagraph("Injected value", injectedValue)
                                + IssueFactory.evidenceParagraph("Write request status", String.valueOf(writeStatus))
                                + IssueFactory.evidenceParagraph("Independent read-back URL", readReq.url())
                                + "<p>An unsolicited privileged field was added to the write request body. "
                                + "A SEPARATE, subsequent read request (not merely the write response echo) "
                                + "confirms the injected value was actually persisted server-side, proving "
                                + "the backend binds raw request JSON onto the model without an explicit "
                                + "field allow-list.</p>",
                        "Use explicit DTOs/allow-lists for bindable fields on every write endpoint. Never "
                                + "bind a raw request body directly onto a persistence/ORM model. Reject "
                                + "requests containing unrecognized fields (e.g. Jackson's "
                                + "FAIL_ON_UNKNOWN_PROPERTIES, or strict JSON-schema validation) rather than "
                                + "silently ignoring or, worse, silently accepting them.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        "Mass assignment vulnerabilities occur when an API automatically binds client-"
                                + "supplied request fields onto internal model attributes without restricting "
                                + "which fields are allowed to be set by the caller, enabling privilege "
                                + "escalation or data tampering via unexpected fields.",
                        base, writeResult, readResult));
                break; // one confirmed finding per base request is enough signal; avoid hammering further
            }
        }

        return issues;
    }

    private String injectField(String jsonBody, String field, String value) {
        try {
            String trimmed = jsonBody.trim();
            if (!trimmed.startsWith("{")) return jsonBody; // only handle JSON objects, not arrays/other shapes
            int lastBrace = trimmed.lastIndexOf('}');
            if (lastBrace <= 0) return jsonBody;
            String inner = trimmed.substring(1, lastBrace).trim();
            String injected = "\"" + field + "\":" + value;
            String newInner = inner.isEmpty() ? injected : inner + "," + injected;
            return "{" + newInner + "}";
        } catch (Exception e) {
            return jsonBody;
        }
    }

    private boolean valueActuallyPersisted(String readBody, String field, String injectedValue) {
        Matcher m = Pattern.compile(Pattern.quote("\"" + field + "\"") + "\\s*:\\s*" + Pattern.quote(injectedValue))
                .matcher(readBody);
        return m.find();
    }
}
