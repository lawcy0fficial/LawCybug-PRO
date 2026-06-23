package pro.lawcybug.scanner.workflow;

import pro.lawcybug.scanner.core.ScanSettings;

import java.util.Set;

/**
 * Every chain/workflow-based detector (BOLA chains, ATO chains, business
 * logic chains) routes its extra requests through this guard rather than
 * calling api().http().sendRequest(...) unconditionally. Centralizes three
 * enterprise-required safety properties in one place instead of trusting
 * every detector author to reimplement them correctly:
 *
 *   1. SAFE MODE -- mutating HTTP methods on steps explicitly marked as
 *      "mutating" (refund, coupon-apply, password-reset, role-change, etc.)
 *      are blocked unless the operator has explicitly turned Safe Mode off
 *      for this engagement.
 *   2. PER-CHAIN REQUEST BUDGET -- a single base request can never trigger
 *      an unbounded number of extra requests through a chain.
 *   3. THROTTLING -- a minimum delay between consecutive chain requests so
 *      a target's WAF/rate-limiter (or just its production capacity) isn't
 *      hammered by a scan running many chains in parallel.
 */
public final class ChainGuard {

    private static final Set<String> MUTATING_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    private final ScanSettings settings;
    private final ThreadLocal<Integer> requestsUsedInCurrentChain = ThreadLocal.withInitial(() -> 0);
    private volatile long lastRequestAtMillis = 0;

    public ChainGuard(ScanSettings settings) {
        this.settings = settings;
    }

    /** Call once at the start of each chain execution (per base request) to reset the per-chain budget. */
    public void beginChain() {
        requestsUsedInCurrentChain.set(0);
    }

    /**
     * @param httpMethod   the method of the step about to be sent
     * @param isMutating   whether this step is declared as a state-mutating
     *                     operation (the detector author marks this explicitly;
     *                     we don't try to infer it from the method alone, since
     *                     plenty of REST APIs mutate state via POST-as-read too)
     * @return true if the step is allowed to be sent, false if it must be skipped
     */
    public synchronized boolean allow(String httpMethod, boolean isMutating) {
        if (isMutating && settings.isSafeModeEnabled()) {
            return false;
        }
        int used = requestsUsedInCurrentChain.get();
        if (used >= settings.getMaxRequestsPerChain()) {
            return false;
        }
        requestsUsedInCurrentChain.set(used + 1);
        throttle();
        return true;
    }

    /** Convenience overload: infers mutating-ness from the HTTP method as a fallback only. */
    public boolean allow(String httpMethod) {
        return allow(httpMethod, MUTATING_METHODS.contains(httpMethod == null ? "" : httpMethod.toUpperCase()));
    }

    private void throttle() {
        long delay = settings.getChainRequestDelayMillis();
        if (delay <= 0) return;
        long now = System.currentTimeMillis();
        long elapsedSinceLast = now - lastRequestAtMillis;
        if (elapsedSinceLast < delay) {
            try {
                Thread.sleep(delay - elapsedSinceLast);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        lastRequestAtMillis = System.currentTimeMillis();
    }
}
