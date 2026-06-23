package pro.lawcybug.scanner.detectors.idor;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IDOR / Broken Object Level Authorization (BOLA) CONFIRMATION detector.
 *
 * This is fundamentally different from the JSON rule engine's passive
 * "sequential ID" heuristic: that one only flags a *precondition*. This
 * detector actually CONFIRMS the vulnerability by replaying the exact
 * same request -- targeting the exact same object ID -- under a SECOND,
 * independent authenticated identity (configured by the user in Settings
 * as settings.secondarySessionHeaderValue) and checking whether that
 * second identity can still retrieve/modify the first identity's object.
 *
 * Requires the user to:
 *   1. Log in to the target app as TWO separate accounts (victim + attacker).
 *   2. Capture one authenticated request as the VICTIM (this becomes the
 *      "base" request Burp scans normally).
 *   3. Paste the ATTACKER account's session header value into the
 *      Settings tab (Authorization/Cookie value only, e.g. "Bearer eyJ..."
 *      or "session=abc123").
 *
 * The detector only fires on insertion points that look like an object
 * identifier (numeric ID, UUID) in the path or a parameter, to avoid
 * wasting requests replaying every parameter on every endpoint.
 */
public final class IdorAuthorizationDetector implements ActiveDetector {

    public static final String ID = "authz.idor.confirm";

    private static final Pattern NUMERIC_ID   = Pattern.compile("^\\d{1,15}$");
    private static final Pattern UUID_ID      = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern ID_LIKE_NAME = Pattern.compile(
            "(?i)\\b(id|uid|user_?id|account_?id|order_?id|invoice_?id|object_?id|doc_?id|file_?id)\\b");

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "IDOR / BOLA Confirmation (Cross-Identity Replay)"; }
    @Override public String description() { return "Replays the base request under a second configured identity to confirm object-level authorization bypass."; }
    @Override public String category()    { return "Access Control"; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.response() == null) return issues;

        if (!ctx.settings().hasSecondarySession()) {
            // Gracefully skip -- this detector cannot confirm anything
            // without a second identity configured. No false signal raised.
            return issues;
        }

        String value = insertionPoint.baseValue().toString();
        if (!looksLikeObjectIdentifier(insertionPoint.name(), value)) {
            return issues;
        }

        // Build a request identical to the base request (same object ID,
        // same path/params) but with the auth credential swapped to the
        // SECOND identity.
        HttpRequest victimRequest = base.request();
        HttpRequest attackerRequest = swapIdentity(victimRequest, ctx);
        if (attackerRequest == null) return issues;

        HttpRequestResponse attackerResult = ctx.api().http().sendRequest(attackerRequest);
        if (attackerResult.response() == null) return issues;

        int victimStatus = base.response().statusCode();
        int attackerStatus = attackerResult.response().statusCode();

        boolean victimSucceeded   = victimStatus >= 200 && victimStatus < 300;
        boolean attackerSucceeded = attackerStatus >= 200 && attackerStatus < 300;

        if (!victimSucceeded || !attackerSucceeded) {
            return issues; // can't confirm cross-identity leak if either request itself failed
        }

        String victimBody   = base.response().bodyToString();
        String attackerBody = attackerResult.response().bodyToString();

        // Confirmation heuristic: the attacker identity, querying the exact
        // same object ID, got back a response with substantially similar
        // structure/content to the victim's own response (not a generic
        // "not found"/empty-state page). We use a cheap similarity check:
        // shared length proportion + shared non-trivial substring anchor.
        double similarity = bodySimilarity(victimBody, attackerBody);

        if (similarity >= 0.6 && attackerBody.length() > 40) {
            AuditIssueConfidence confidence = similarity >= 0.85
                    ? AuditIssueConfidence.CERTAIN
                    : AuditIssueConfidence.FIRM;

            issues.add(IssueFactory.build(
                    "IDOR / Broken Object Level Authorization (BOLA) Confirmed",
                    IssueFactory.evidenceParagraph("Object identifier parameter", insertionPoint.name())
                            + IssueFactory.evidenceParagraph("Object identifier value", value)
                            + IssueFactory.evidenceParagraph("Victim request status", String.valueOf(victimStatus))
                            + IssueFactory.evidenceParagraph("Second-identity request status", String.valueOf(attackerStatus))
                            + IssueFactory.evidenceParagraph("Response body similarity score", String.format("%.2f", similarity))
                            + "<p>The second, independently authenticated identity configured in Settings "
                            + "was able to retrieve a response substantially identical to the original "
                            + "(victim) identity's response for the SAME object identifier, without ever "
                            + "being granted access to that specific object. This confirms an object-level "
                            + "authorization bypass (IDOR/BOLA) rather than merely a precondition.</p>",
                    "Enforce object-level authorization on every resource-returning/modifying endpoint: "
                            + "verify server-side that the authenticated principal actually owns or has been "
                            + "explicitly granted access to the SPECIFIC object id requested -- never rely on "
                            + "the object id being hard to guess, and never rely on authentication alone.",
                    base.request().url(),
                    AuditIssueSeverity.HIGH,
                    confidence,
                    "Insecure Direct Object References occur when an application uses a user-supplied "
                            + "identifier to access an object without verifying the requester is authorized "
                            + "to access that specific object.",
                    base, attackerResult));
        }

        return issues;
    }

    private boolean looksLikeObjectIdentifier(String paramName, String value) {
        if (value == null || value.isEmpty()) return false;
        boolean nameLooksLikeId = paramName != null && ID_LIKE_NAME.matcher(paramName).find();
        boolean valueLooksLikeId = NUMERIC_ID.matcher(value).matches() || UUID_ID.matcher(value).matches();
        // Require value shape OR name hint, but skip pure single-digit values
        // (booleans, page=1, etc.) which are too noisy to be worth a full
        // round-trip replay.
        if (NUMERIC_ID.matcher(value).matches() && value.length() < 2) return false;
        return valueLooksLikeId || (nameLooksLikeId && value.length() >= 2);
    }

    /** Returns a new HttpRequest with the configured auth header swapped for the secondary identity's value. */
    private HttpRequest swapIdentity(HttpRequest original, DetectorContext ctx) {
        try {
            String headerName = ctx.settings().getSecondarySessionHeaderName();
            String headerValue = ctx.settings().getSecondarySessionHeaderValue();
            if (headerValue == null || headerValue.isBlank()) return null;

            HttpRequest updated = original;
            boolean hadHeader = original.headers().stream()
                    .anyMatch(h -> h.name().equalsIgnoreCase(headerName));
            if (hadHeader) {
                updated = updated.withRemovedHeader(headerName);
            }
            updated = updated.withAddedHeader(headerName, headerValue);
            return updated;
        } catch (Exception e) {
            ctx.api().logging().logToError("[LawCyBug.pro] IDOR detector identity-swap error: " + e);
            return null;
        }
    }

    /**
     * Cheap structural similarity: proportion of shared length plus a check
     * that a meaningfully long contiguous substring is shared between the
     * two bodies (catching JSON key/value overlap without needing a real
     * diff library, which keeps this detector dependency-free).
     */
    private double bodySimilarity(String a, String b) {
        if (a.isEmpty() || b.isEmpty()) return 0.0;
        int shorter = Math.min(a.length(), b.length());
        int longer = Math.max(a.length(), b.length());
        double lengthRatio = (double) shorter / longer;

        int anchorLen = Math.min(60, shorter / 2);
        if (anchorLen < 10) return lengthRatio; // too short to anchor-match meaningfully

        String anchor = a.substring(Math.max(0, a.length() / 2 - anchorLen / 2),
                Math.min(a.length(), a.length() / 2 + anchorLen / 2));
        boolean anchorShared = !anchor.isBlank() && b.contains(anchor);

        return anchorShared ? Math.max(lengthRatio, 0.8) : lengthRatio * 0.5;
    }
}
