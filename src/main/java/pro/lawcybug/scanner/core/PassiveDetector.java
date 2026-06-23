package pro.lawcybug.scanner.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

/**
 * A passive detector only ever looks at a request/response pair that
 * Burp has already captured through normal traffic (Proxy, Repeater,
 * spidering, etc.). It MUST NOT make any new HTTP requests of its own
 * -- that's a hard rule of Burp's passive scanner contract.
 */
public interface PassiveDetector {

    /** Stable, unique id used for settings toggles and consolidation. */
    String id();

    /** Human-readable name shown in the Settings tab. */
    String displayName();

    /** One-line description shown as a tooltip / in the Rules tab. */
    String description();

    /**
     * Analyze the given request/response. Return an empty list if
     * nothing was found. Implementations should be fast and must
     * never throw checked exceptions across this boundary -- wrap
     * anything risky in try/catch internally if needed, the engine
     * also catches unchecked exceptions defensively per-detector.
     */
    List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse baseRequestResponse);
}
