package pro.lawcybug.scanner.core;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Prevents "whole-request" active detectors -- ones whose logic depends
 * on the full base request rather than on which specific insertion point
 * Burp happens to be testing (e.g. RaceConditionDetector, AuthzBypassDetector,
 * MassAssignmentConfirmDetector) -- from re-running their full logic once
 * per insertion point on the SAME base request.
 *
 * Burp's active-scan contract calls ScanCheck.activeAudit(...) once per
 * insertion point selected for a given base request. For detectors that
 * mutate the insertion point's value, that's correct and necessary. But
 * for detectors that operate on the request as a whole and ignore the
 * insertion point entirely, that calling convention means a request with
 * N parameters triggers N full executions of logic that doesn't even
 * vary by parameter -- multiplying side-effecting write requests, burst
 * concurrent requests, and bypass probes by N for zero added coverage,
 * and risking real side effects against the target (e.g. N x duplicate
 * orders, N x redemption attempts).
 *
 * Fingerprint = method + URL + body-hash. The TTL is intentionally short
 * (long enough to cover one scanner pass over a single base request's
 * insertion points, which arrive back-to-back from the same audit) rather
 * than a permanent "never scan this again" cache -- so re-scanning the
 * same endpoint later (e.g. a fresh manual "Scan defined insertion
 * points" run, or a follow-up Burp Scanner pass) is not silently and
 * permanently skipped.
 */
public final class RequestFingerprintGuard {

    private static final long DEFAULT_TTL_MILLIS = 5_000;
    private static final int MAX_TRACKED_ENTRIES = 5_000;

    private final long ttlMillis;
    private final ConcurrentHashMap<String, Long> seenAt = new ConcurrentHashMap<>();

    public RequestFingerprintGuard() {
        this(DEFAULT_TTL_MILLIS);
    }

    public RequestFingerprintGuard(long ttlMillis) {
        this.ttlMillis = ttlMillis;
    }

    /**
     * Returns true (and claims the fingerprint) only for the first caller
     * within the TTL window for this exact request fingerprint. Every
     * subsequent caller within the window gets false and should return
     * an empty issue list without sending any further requests.
     */
    public boolean claim(HttpRequestResponse base) {
        String fingerprint = fingerprint(base);
        long now = System.currentTimeMillis();
        Long previous = seenAt.putIfAbsent(fingerprint, now);
        if (previous != null) {
            if ((now - previous) < ttlMillis) {
                return false;
            }
            // Outside the TTL window -- refresh the timestamp and allow it through again.
            seenAt.put(fingerprint, now);
        }
        opportunisticCleanup(now);
        return true;
    }

    private String fingerprint(HttpRequestResponse base) {
        String method = base.request().method();
        String url = base.request().url();
        String body = base.request().bodyToString();
        int bodyHash = body == null ? 0 : body.hashCode();
        return method + "|" + url + "|" + bodyHash;
    }

    private void opportunisticCleanup(long now) {
        if (seenAt.size() > MAX_TRACKED_ENTRIES) {
            seenAt.entrySet().removeIf(e -> (now - e.getValue()) > ttlMillis);
        }
    }
}
