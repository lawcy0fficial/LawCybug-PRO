package pro.lawcybug.scanner.util;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Time-based blind injection (SQLi, command injection, SSTI, etc.) is the
 * single biggest source of false positives in cheap scanners, because a
 * single slow response can be network jitter, server GC pause, or just a
 * naturally slow endpoint -- not a vulnerability. This class implements a
 * simple but effective statistical approach used by this extension for
 * every time-based detector:
 *
 *   1. Measure a baseline (unmodified / "false-condition") request N times.
 *   2. Measure the "true-condition" (delay-triggering) payload N times.
 *   3. Only report when the MINIMUM delayed-response time clearly exceeds
 *      both the baseline's MAXIMUM observed time AND the requested delay
 *      threshold, with margin -- a single slow sample is never enough.
 *
 * This trades a little speed for materially fewer false positives, which
 * matters far more than raw payload count for an "accuracy first" tool.
 */
public final class TimingUtils {

    private TimingUtils() {
    }

    public static final class TimingResult {
        public final List<Long> millis;

        public TimingResult(List<Long> millis) {
            this.millis = millis;
        }

        public long min() {
            return Collections.min(millis);
        }

        public long max() {
            return Collections.max(millis);
        }

        public double average() {
            return millis.stream().mapToLong(Long::longValue).average().orElse(0);
        }
    }

    /** Sends the given request N times and records wall-clock latency per request. */
    public static TimingResult measure(Http http, HttpRequest request, int repeats) {
        List<Long> times = new ArrayList<>(repeats);
        for (int i = 0; i < repeats; i++) {
            long start = System.nanoTime();
            HttpRequestResponse response = http.sendRequest(request);
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
            // Touch the response so the request is not optimized away and to
            // allow callers to inspect it if they keep their own reference.
            if (response.response() == null) {
                // Connection failed / timed out -- treat as a very large delay
                // rather than silently skipping, so it doesn't mask a real
                // positive by under-counting samples.
                elapsedMs = Math.max(elapsedMs, 60_000L);
            }
            times.add(elapsedMs);
        }
        return new TimingResult(times);
    }

    /**
     * Decide whether a delayed-payload timing result is convincing evidence
     * of a time-based blind vulnerability, given a baseline and the delay
     * (in seconds) the payload was supposed to introduce.
     */
    public static boolean isConvincingDelay(TimingResult baseline, TimingResult delayed, long requestedDelaySeconds) {
        long requestedDelayMs = requestedDelaySeconds * 1000L;
        // The slowest baseline sample sets our noise floor.
        long noiseFloor = baseline.max();
        // Require the fastest delayed sample to still clearly exceed both
        // the noise floor and a good fraction of the requested delay.
        long minDelayed = delayed.min();
        long requiredThreshold = Math.max(noiseFloor + (requestedDelayMs / 2), (requestedDelayMs * 60) / 100);
        return minDelayed >= requiredThreshold;
    }
}
