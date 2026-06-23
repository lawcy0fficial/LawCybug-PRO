package pro.lawcybug.scanner.detectors.takeover;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Account Takeover CONFIRMATION detector, focused on the single most
 * common, single-request-replayable root cause: password-reset / email-
 * verification / magic-link TOKEN REUSE.
 *
 * Real account-takeover chains are usually multi-step and app-specific
 * (request reset -> receive email -> click link -> set new password),
 * which this generic scanner cannot fully automate without access to the
 * victim's inbox. What IS generically testable and extremely high-signal:
 * whether a reset/verification token, once used successfully, can be
 * used AGAIN. A token that survives reuse means:
 *   - an attacker who intercepts/logs a token (proxy logs, Referer leak,
 *     browser history, a shared analytics beacon) can use it indefinitely
 *     rather than it being invalidated after first use, and
 *   - concurrent/parallel use windows exist for the same race-condition
 *     class of issue applied specifically to auth tokens.
 *
 * This detector triggers on insertion points whose parameter name/value
 * shape looks like a reset/verification token, REPLAYS the exact same
 * request a second time, and flags CONFIRMED account-takeover risk if
 * the second use also succeeds (rather than receiving an "already used /
 * invalid token" rejection).
 */
public final class AccountTakeoverDetector implements ActiveDetector {

    public static final String ID = "authn.account_takeover.token_replay";

    private static final Pattern TOKEN_PARAM_NAME = Pattern.compile(
            "(?i)\\b(reset_?token|verif(y|ication)_?token|invite_?token|magic_?link|otp|confirmation_?code|activation_?code)\\b");

    private static final Pattern TOKEN_VALUE_SHAPE = Pattern.compile("^[A-Za-z0-9_\\-\\.]{16,}$");

    private static final Pattern ALREADY_USED_HINT = Pattern.compile(
            "(?i)(already (used|redeemed|verified)|token (expired|invalid)|invalid or expired|link has expired)");

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Account Takeover - Reset/Verification Token Replay"; }
    @Override public String description() { return "Replays a password-reset/verification token a second time to confirm single-use enforcement is missing."; }
    @Override public String category()    { return "Authentication"; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.response() == null) return issues;

        String paramName = insertionPoint.name();
        String value = insertionPoint.baseValue().toString();

        boolean nameMatches = paramName != null && TOKEN_PARAM_NAME.matcher(paramName).find();
        boolean urlMatches = TOKEN_PARAM_NAME.matcher(base.request().url()).find();
        boolean valueShapeMatches = TOKEN_VALUE_SHAPE.matcher(value).matches();

        if (!(nameMatches || urlMatches) || !valueShapeMatches) {
            return issues; // not confidently a reset/verification-style token
        }

        int firstUseStatus = base.response().statusCode();
        boolean firstUseSucceeded = firstUseStatus >= 200 && firstUseStatus < 300
                && !ALREADY_USED_HINT.matcher(base.response().bodyToString()).find();

        if (!firstUseSucceeded) {
            return issues; // the base traffic capture wasn't itself a successful first use; nothing to confirm
        }

        // Replay the EXACT same request (same token value) a second time.
        HttpRequestResponse secondUse = ctx.api().http().sendRequest(base.request());
        if (secondUse.response() == null) return issues;

        int secondStatus = secondUse.response().statusCode();
        String secondBody = secondUse.response().bodyToString();
        boolean secondUseSucceeded = secondStatus >= 200 && secondStatus < 300
                && !ALREADY_USED_HINT.matcher(secondBody == null ? "" : secondBody).find();

        if (secondUseSucceeded) {
            issues.add(IssueFactory.build(
                    "Account Takeover Risk - Reset/Verification Token Reusable (No Single-Use Enforcement)",
                    IssueFactory.evidenceParagraph("Token parameter", paramName != null ? paramName : "(in URL path)")
                            + IssueFactory.evidenceParagraph("Token value (as captured)", value)
                            + IssueFactory.evidenceParagraph("First use status", String.valueOf(firstUseStatus))
                            + IssueFactory.evidenceParagraph("Second use status", String.valueOf(secondStatus))
                            + "<p>The exact same password-reset/verification/invite token was successfully "
                            + "replayed a second time without the server rejecting it as already used. Any "
                            + "token that survives reuse is far more dangerous than a normal single-use design: "
                            + "if it is ever exposed via proxy/server logs, browser history, a Referer leak, "
                            + "an analytics beacon, or shoulder-surfing, an attacker can use it indefinitely "
                            + "to take over the account (or repeatedly trigger the action it gates), rather "
                            + "than the exposure window being limited to a single use.</p>",
                    "Invalidate reset/verification/invite tokens immediately and atomically on first "
                            + "successful use (e.g. delete the token row or flip a used flag inside the same "
                            + "database transaction that performs the password change/verification), and "
                            + "give all such tokens a short absolute expiry independent of use.",
                    base.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    "Reusable single-purpose authentication tokens significantly widen the exposure window "
                            + "for account takeover: a token captured once (via logs, history, or a leaked link) "
                            + "remains a standing credential rather than being burned after first legitimate use.",
                    base, secondUse));
        }

        return issues;
    }
}
