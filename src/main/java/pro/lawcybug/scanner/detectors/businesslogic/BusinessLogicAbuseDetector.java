package pro.lawcybug.scanner.detectors.businesslogic;

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
import pro.lawcybug.scanner.workflow.SessionIdentity;
import pro.lawcybug.scanner.workflow.WorkflowEngine;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Business-logic abuse checks that pure payload/regex matching structurally
 * cannot express, because the "vulnerability" is a valid request the
 * application simply shouldn't allow given its own rules:
 *
 *   1. NEGATIVE-VALUE TAMPERING: quantity/price/amount fields flipped
 *      negative (quantity=-1, price=-100, amount=-50) on cart/order/wallet
 *      endpoints. A naive total = price * quantity calculation can let a
 *      negative quantity or price reduce a bill below zero, effectively
 *      crediting the attacker, or let a negative "amount" on a transfer/
 *      withdrawal endpoint reverse the direction of funds flow.
 *
 *   2. SEQUENTIAL REUSE ABUSE: coupon/voucher/promo-code application
 *      replayed a second time, back-to-back (NOT concurrently -- that's
 *      the existing RaceConditionDetector's job). This catches reuse bugs
 *      where the server fails to mark a single-use code as consumed at
 *      all, as opposed to race-only bugs where it marks it consumed too
 *      slowly. Both are real bug classes bounty programs pay for, and
 *      they require different proof: race needs concurrency, plain reuse
 *      just needs "did it work twice when it should only work once".
 *
 * Both checks use the WorkflowEngine/ChainGuard so they respect Safe Mode
 * (these are inherently mutating -- applying a coupon or submitting an
 * order changes real state) and the per-chain request budget.
 */
public final class BusinessLogicAbuseDetector implements ActiveDetector {

    private static final String ID = "business-logic-abuse";

    private static final Pattern NUMERIC_FIELD =
            Pattern.compile("\"(qty|quantity|amount|price|total|count|units|value)\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern COUPON_FIELD =
            Pattern.compile("\"(coupon|promo|voucher|discount[_-]?code|referral[_-]?code)\"\\s*:\\s*\"([^\"]+)\"",
                    Pattern.CASE_INSENSITIVE);

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Business Logic Abuse (Negative Values + Reuse)";
    }

    @Override
    public String description() {
        return "Tests negative quantity/price/amount tampering and sequential single-use-code "
                + "reuse, both of which require business-logic awareness rather than payload matching.";
    }

    @Override
    public String category() {
        return "Business Logic";
    }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse baseRequestResponse,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpRequest base = baseRequestResponse.request();
        String body = base.bodyToString();
        if (body == null || body.isBlank()) {
            return issues;
        }

        SessionIdentity actor = ctx.identityRegistry().byRole(SessionIdentity.Role.VICTIM)
                .orElse(ctx.identityRegistry().byRole(SessionIdentity.Role.ATTACKER).orElse(null));

        checkNegativeValueTampering(ctx, base, body, actor, issues);
        checkSequentialReuse(ctx, base, body, actor, issues);

        return issues;
    }

    // -----------------------------------------------------------------
    private void checkNegativeValueTampering(DetectorContext ctx, HttpRequest base, String body,
                                              SessionIdentity actor, List<AuditIssue> issues) {
        Matcher m = NUMERIC_FIELD.matcher(body);
        if (!m.find()) return;

        String field = m.group(1);
        String original = m.group(2);
        if (original.startsWith("-")) return; // already negative in the wild -- not our tamper to claim

        String tamperedBody = body.substring(0, m.start(2)) + "-" + original + body.substring(m.end(2));

        List<WorkflowEngine.Step> steps = new ArrayList<>();
        steps.add(new WorkflowEngine.Step("Submit negative " + field,
                vars -> base.withBody(ByteArray.byteArray(tamperedBody))).asMutating());

        WorkflowEngine.ChainResult result = ctx.workflowEngine().run(steps, actor);
        if (result.steps.isEmpty()) return; // blocked by Safe Mode / budget

        WorkflowEngine.StepResult step = result.steps.get(0);
        if (!step.succeeded || step.requestResponse.response() == null) return;

        int status = step.requestResponse.response().statusCode();
        String respBody = step.requestResponse.response().bodyToString();

        boolean acceptedWithoutValidation = status >= 200 && status < 300
                && !mentionsValidationError(respBody);

        if (acceptedWithoutValidation) {
            issues.add(IssueFactory.build(
                    "Negative Value Accepted (" + field + ")",
                    "<p>Submitting a negative value for the <code>" + IssueFactory.escapeHtml(field)
                            + "</code> field (original: <code>" + IssueFactory.escapeHtml(original)
                            + "</code>, tampered: <code>-" + IssueFactory.escapeHtml(original)
                            + "</code>) was accepted with HTTP " + status + " and no visible validation error. "
                            + "If this value feeds a total/balance calculation server-side (e.g. "
                            + "<code>total = price * quantity</code> or a wallet credit/debit), a negative "
                            + "value can invert the direction of money flow or push a total below zero.</p>"
                            + IssueFactory.evidenceParagraph("Endpoint", base.url())
                            + IssueFactory.evidenceParagraph("Field", field),
                    "<p>Validate that quantity/price/amount fields are non-negative (and within sane bounds) "
                            + "server-side before they participate in any financial calculation. Never trust "
                            + "client-supplied numeric fields used in pricing/balance logic.</p>",
                    base.url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.TENTATIVE,
                    "<p>This is a LEAD, not a confirmed financial-impact finding -- manually verify the "
                            + "actual total/balance produced reflects the tampered value before reporting.</p>",
                    step.requestResponse
            ));
        }
    }

    // -----------------------------------------------------------------
    private void checkSequentialReuse(DetectorContext ctx, HttpRequest base, String body,
                                       SessionIdentity actor, List<AuditIssue> issues) {
        Matcher m = COUPON_FIELD.matcher(body);
        if (!m.find()) return;

        String fieldName = m.group(1);
        String code = m.group(2);

        List<WorkflowEngine.Step> steps = new ArrayList<>();
        steps.add(new WorkflowEngine.Step("Apply " + fieldName + " (first)",
                vars -> base.withBody(ByteArray.byteArray(body))).asMutating());
        steps.add(new WorkflowEngine.Step("Apply " + fieldName + " (second, sequential replay)",
                vars -> base.withBody(ByteArray.byteArray(body))).asMutating());

        WorkflowEngine.ChainResult result = ctx.workflowEngine().run(steps, actor);
        if (result.steps.size() < 2) return; // Safe Mode blocked it, or first attempt itself failed

        WorkflowEngine.StepResult first = result.steps.get(0);
        WorkflowEngine.StepResult second = result.steps.get(1);
        if (!first.succeeded || !second.succeeded) return;
        if (first.requestResponse.response() == null || second.requestResponse.response() == null) return;

        int statusFirst = first.requestResponse.response().statusCode();
        int statusSecond = second.requestResponse.response().statusCode();
        String bodySecond = second.requestResponse.response().bodyToString();

        boolean bothSucceededIdentically = statusFirst >= 200 && statusFirst < 300
                && statusSecond >= 200 && statusSecond < 300
                && !mentionsValidationError(bodySecond)
                && !mentionsAlreadyUsedError(bodySecond);

        if (bothSucceededIdentically) {
            issues.add(IssueFactory.build(
                    "Single-Use Code Reuse (" + fieldName + ")",
                    "<p>Replaying the same <code>" + IssueFactory.escapeHtml(fieldName) + "</code> value <code>"
                            + IssueFactory.escapeHtml(code) + "</code> a second time, sequentially (not "
                            + "concurrently), succeeded again with HTTP " + statusSecond
                            + " and no \"already used\"/validation error. A single-use code should be rejected "
                            + "on the second application -- this indicates the server isn't marking codes as "
                            + "consumed at all, rather than a timing/race issue.</p>"
                            + IssueFactory.evidenceParagraph("Endpoint", base.url())
                            + IssueFactory.evidenceParagraph("Field", fieldName)
                            + IssueFactory.evidenceParagraph("Value", code),
                    "<p>Mark single-use codes/resources as consumed atomically on first successful use, and "
                            + "reject all subsequent applications regardless of timing.</p>",
                    base.url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    "<p>Distinct from the race-condition class of bug: this fires even with two fully "
                            + "sequential, non-concurrent requests, meaning there's no enforcement at all "
                            + "rather than merely a narrow timing window.</p>",
                    first.requestResponse,
                    second.requestResponse
            ));
        }
    }

    private boolean mentionsValidationError(String body) {
        if (body == null) return false;
        String lower = body.toLowerCase();
        return lower.contains("invalid") || lower.contains("error") || lower.contains("must be")
                || lower.contains("negative") || lower.contains("out of range") || lower.contains("validation");
    }

    private boolean mentionsAlreadyUsedError(String body) {
        if (body == null) return false;
        String lower = body.toLowerCase();
        return lower.contains("already used") || lower.contains("already redeemed")
                || lower.contains("already applied") || lower.contains("expired")
                || lower.contains("not valid") || lower.contains("not found");
    }
}
