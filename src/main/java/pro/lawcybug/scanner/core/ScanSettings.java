package pro.lawcybug.scanner.core;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Central, mutable settings object. The UI (Settings tab) mutates this,
 * detectors read from it on every call. Thread-safe enough for our use:
 * Burp drives scan checks from a pool of scanner threads, settings are
 * read far more often than written (written only via user clicks on the
 * EDT), so we use simple volatile-backed fields + a concurrent map for
 * per-detector toggles instead of full locking.
 */
public final class ScanSettings {

    public enum Intensity {
        QUICK("Quick - minimal payloads, fastest, lowest coverage"),
        NORMAL("Normal - balanced payload set (recommended)"),
        THOROUGH("Thorough - full payload set, slower, highest coverage");

        public final String description;

        Intensity(String description) {
            this.description = description;
        }
    }

    private volatile Intensity intensity = Intensity.NORMAL;
    private volatile boolean collaboratorEnabled = true;
    private volatile int timeBasedRequestRepeats = 3;
    private volatile long timeBasedDelaySeconds = 8;
    private volatile boolean onlyScanInScope = true;

    /**
     * Raw header VALUE (e.g. "Bearer eyJ..." or "session=abc123") representing
     * a SECOND, lower-privileged authenticated identity. IDOR / Authorization-
     * Bypass detectors replay the same request swapping the primary session's
     * auth header for this one and compare results -- this is the only way to
     * confirm object-level/function-level authorization issues rather than
     * just flagging preconditions. Leave blank to disable those checks (they
     * degrade gracefully to "skipped, no secondary session configured").
     */
    private volatile String secondarySessionHeaderValue = "";

    /** Name of the header to replace when swapping in the secondary session (e.g. "Authorization" or "Cookie"). */
    private volatile String secondarySessionHeaderName = "Authorization";

    private volatile int raceConditionConcurrency = 20;

    /**
     * SAFE MODE: when true, any chain/workflow/business-logic detector that
     * would send a state-MUTATING request (POST/PUT/PATCH/DELETE on a step
     * marked as mutating) must skip it instead. Defaults to true -- mutating
     * chains (refund race, coupon reuse, ATO takeover) are opt-in per
     * engagement, never on by default, since they can create real orders,
     * real refunds, or real password resets against a live target.
     */
    private volatile boolean safeModeEnabled = true;

    /** Hard ceiling on extra requests any single chain/workflow detector may send for one base request. */
    private volatile int maxRequestsPerChain = 12;

    /** Minimum delay between consecutive requests sent by chain/workflow detectors, to avoid hammering targets. */
    private volatile long chainRequestDelayMillis = 150;

    // Per-detector enable/disable, keyed by detector id. Defaults to enabled
    // for any id not explicitly present.
    private final Map<String, Boolean> detectorToggles = new LinkedHashMap<>();

    private final CopyOnWriteArrayList<Consumer<ScanSettings>> changeListeners = new CopyOnWriteArrayList<>();

    public synchronized boolean isDetectorEnabled(String detectorId) {
        return detectorToggles.getOrDefault(detectorId, Boolean.TRUE);
    }

    public synchronized void setDetectorEnabled(String detectorId, boolean enabled) {
        detectorToggles.put(detectorId, enabled);
        fireChanged();
    }

    public synchronized Map<String, Boolean> snapshotToggles() {
        return new LinkedHashMap<>(detectorToggles);
    }

    public Intensity getIntensity() {
        return intensity;
    }

    public void setIntensity(Intensity intensity) {
        this.intensity = intensity;
        fireChanged();
    }

    public boolean isCollaboratorEnabled() {
        return collaboratorEnabled;
    }

    public void setCollaboratorEnabled(boolean collaboratorEnabled) {
        this.collaboratorEnabled = collaboratorEnabled;
        fireChanged();
    }

    public int getTimeBasedRequestRepeats() {
        return timeBasedRequestRepeats;
    }

    public void setTimeBasedRequestRepeats(int timeBasedRequestRepeats) {
        this.timeBasedRequestRepeats = Math.max(1, timeBasedRequestRepeats);
        fireChanged();
    }

    public long getTimeBasedDelaySeconds() {
        return timeBasedDelaySeconds;
    }

    public void setTimeBasedDelaySeconds(long timeBasedDelaySeconds) {
        this.timeBasedDelaySeconds = Math.max(2, timeBasedDelaySeconds);
        fireChanged();
    }

    public boolean isOnlyScanInScope() {
        return onlyScanInScope;
    }

    public void setOnlyScanInScope(boolean onlyScanInScope) {
        this.onlyScanInScope = onlyScanInScope;
        fireChanged();
    }

    public String getSecondarySessionHeaderValue() {
        return secondarySessionHeaderValue;
    }

    public void setSecondarySessionHeaderValue(String value) {
        this.secondarySessionHeaderValue = value == null ? "" : value;
        fireChanged();
    }

    public String getSecondarySessionHeaderName() {
        return secondarySessionHeaderName;
    }

    public void setSecondarySessionHeaderName(String name) {
        this.secondarySessionHeaderName = (name == null || name.isBlank()) ? "Authorization" : name;
        fireChanged();
    }

    public boolean hasSecondarySession() {
        return secondarySessionHeaderValue != null && !secondarySessionHeaderValue.isBlank();
    }

    public int getRaceConditionConcurrency() {
        return raceConditionConcurrency;
    }

    public void setRaceConditionConcurrency(int n) {
        this.raceConditionConcurrency = Math.max(2, Math.min(100, n));
        fireChanged();
    }

    public void addChangeListener(Consumer<ScanSettings> listener) {
        changeListeners.add(listener);
    }

    public boolean isSafeModeEnabled() {
        return safeModeEnabled;
    }

    public void setSafeModeEnabled(boolean safeModeEnabled) {
        this.safeModeEnabled = safeModeEnabled;
        fireChanged();
    }

    public int getMaxRequestsPerChain() {
        return maxRequestsPerChain;
    }

    public void setMaxRequestsPerChain(int n) {
        this.maxRequestsPerChain = Math.max(1, Math.min(50, n));
        fireChanged();
    }

    public long getChainRequestDelayMillis() {
        return chainRequestDelayMillis;
    }

    public void setChainRequestDelayMillis(long ms) {
        this.chainRequestDelayMillis = Math.max(0, ms);
        fireChanged();
    }

    private void fireChanged() {
        for (Consumer<ScanSettings> l : changeListeners) {
            l.accept(this);
        }
    }
}
