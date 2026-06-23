package pro.lawcybug.scanner.detectors.race;

import burp.api.montoya.http.message.HttpRequestResponse;
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
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Race Condition (TOCTOU / single-flight) detector.
 *
 * This is the one bug class that is structurally impossible to express in
 * the single-request JSON rule engine: detection REQUIRES firing many
 * requests at the *same* endpoint, with the *same* session/state, within
 * the smallest possible time window, then checking how many of them
 * "won" -- i.e. how many produced a success outcome that should only be
 * possible once (redeem a single-use coupon, withdraw from a balance,
 * accept a one-time invite, vote once, etc).
 *
 * Approach (based on the well-established "last-byte sync" / barrier-burst
 * technique popularized by James Kettle's race-condition research):
 *   1. Build N identical copies of the base request (same insertion point
 *      value -- we don't even need to vary the payload, we WANT identical
 *      requests).
 *   2. Submit them all to a fixed-size thread pool via a CountDownLatch
 *      barrier so they leave the queue as close to simultaneously as the
 *      JVM/Burp's HTTP client allows.
 *   3. Count how many distinct requests returned a "success" status code
 *      (2xx) AND whether the response body indicates a state-changing
 *      success (rather than e.g. a generic 200 error page).
 *   4. If more than one request succeeded where business logic implies
 *      only one *should* be able to (e.g. redeeming a single-use resource),
 *      flag a confirmed race condition.
 *
 * IMPORTANT CALIBRATION NOTE: this detector cannot know your application's
 * business rules. It flags "more than 1 of N concurrent identical requests
 * succeeded" as a race-condition LEAD. Whether that's actually exploitable
 * (e.g. double-spending a coupon vs. just idempotent-by-design GETs) needs
 * a human to confirm -- which is why it's always raised at FIRM, never
 * CERTAIN, confidence, and only against insertion points that look like
 * state-changing actions (see isLikelyStateChanging()).
 */
public final class RaceConditionDetector implements ActiveDetector {

    public static final String ID = "logic.race_condition";

    private static final Pattern STATE_CHANGE_HINT = Pattern.compile(
            "(?i)(redeem|claim|withdraw|transfer|vote|apply|coupon|invite|accept|checkout|purchase|book|reserve|register|enroll)");

    // This detector ignores the insertion point's value entirely -- it
    // fires a burst against the WHOLE request. Without this guard, Burp
    // calling activeAudit() once per insertion point on the same request
    // would multiply the concurrent burst by the parameter count.
    private final RequestFingerprintGuard guard = new RequestFingerprintGuard();

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Race Condition (Concurrent Single-Flight Bypass)"; }
    @Override public String description() { return "Fires N truly concurrent identical requests to detect single-use/TOCTOU race conditions."; }
    @Override public String category()    { return "Business Logic"; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.request() == null) return issues;

        if (!isLikelyStateChanging(base)) {
            return issues; // avoid wasting requests/noise on clearly read-only endpoints
        }

        if (!guard.claim(base)) {
            return issues; // already ran the full concurrent burst for this exact request very recently
        }

        int concurrency = ctx.settings().getRaceConditionConcurrency();
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(concurrency, 50));
        CountDownLatch startBarrier = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(concurrency);
        AtomicInteger successCount = new AtomicInteger(0);
        List<HttpRequestResponse> successResponses = new CopyOnWriteArrayList<>();

        try {
            for (int i = 0; i < concurrency; i++) {
                pool.submit(() -> {
                    try {
                        startBarrier.await(); // all threads release together
                        HttpRequestResponse result = ctx.api().http().sendRequest(base.request());
                        if (result.response() != null) {
                            int status = result.response().statusCode();
                            if (status >= 200 && status < 300 && !looksLikeGenericErrorBody(result)) {
                                successCount.incrementAndGet();
                                successResponses.add(result);
                            }
                        }
                    } catch (Exception ignored) {
                        // network hiccups under heavy concurrency are expected; don't fail the whole batch
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            // small scheduling delay so all worker threads are parked on
            // await() before we release the barrier -- maximizes true
            // concurrency at the socket level rather than a ramp.
            Thread.sleep(150);
            startBarrier.countDown();
            doneLatch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return issues;
        } finally {
            pool.shutdownNow();
        }

        int succeeded = successCount.get();
        if (succeeded > 1) {
            HttpRequestResponse[] evidence = new HttpRequestResponse[Math.min(3, successResponses.size()) + 1];
            evidence[0] = base;
            for (int i = 0; i < evidence.length - 1; i++) evidence[i + 1] = successResponses.get(i);

            issues.add(IssueFactory.build(
                    "Race Condition - Concurrent Single-Flight Bypass",
                    IssueFactory.evidenceParagraph("Concurrent requests fired", String.valueOf(concurrency))
                            + IssueFactory.evidenceParagraph("Requests that returned a success status", String.valueOf(succeeded))
                            + IssueFactory.evidenceParagraph("Endpoint", base.request().url())
                            + "<p>Out of " + concurrency + " identical requests fired concurrently against an "
                            + "endpoint whose URL/parameters suggest a single-use or balance-limited state "
                            + "change (redeem/withdraw/claim/vote/checkout-style action), " + succeeded
                            + " of them returned a success response. If this action is intended to succeed "
                            + "at most once per eligible state (e.g. redeeming a coupon, withdrawing a fixed "
                            + "balance, accepting a one-time invite), this confirms a Time-Of-Check-To-Time-"
                            + "Of-Use (TOCTOU) race condition allowing the limit to be bypassed by parallel "
                            + "requests.</p>",
                    "Use atomic, database-level operations for any single-use or limited-resource action "
                            + "(e.g. SELECT ... FOR UPDATE, conditional UPDATE ... WHERE balance >= amount, or "
                            + "a unique constraint on a redemption table) so the check-and-use happens as a "
                            + "single atomic unit rather than separate read-then-write steps. Avoid relying on "
                            + "application-level locks alone in horizontally-scaled deployments; use database "
                            + "or distributed-lock primitives instead.",
                    base.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    "Race conditions in state-changing business logic (TOCTOU) allow an attacker to exceed "
                            + "intended limits -- e.g. redeeming a coupon multiple times, withdrawing more than "
                            + "the account balance, or registering for an over-subscribed event -- by sending "
                            + "many requests within the narrow window between the application checking a "
                            + "condition and committing the resulting state change.",
                    evidence));
        }

        return issues;
    }

    private boolean isLikelyStateChanging(HttpRequestResponse base) {
        String method = base.request().method();
        boolean writeMethod = method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")
                || method.equalsIgnoreCase("PATCH") || method.equalsIgnoreCase("DELETE");
        boolean hintInUrl = STATE_CHANGE_HINT.matcher(base.request().url()).find();
        boolean hintInBody = base.request().bodyToString() != null
                && STATE_CHANGE_HINT.matcher(base.request().bodyToString()).find();
        return writeMethod && (hintInUrl || hintInBody);
    }

    private boolean looksLikeGenericErrorBody(HttpRequestResponse r) {
        String body = r.response().bodyToString();
        if (body == null) return false;
        String lower = body.toLowerCase();
        return lower.contains("already redeemed") || lower.contains("already used")
                || lower.contains("insufficient") || lower.contains("not eligible")
                || lower.contains("\"error\"") || lower.contains("\"success\":false");
    }
}
