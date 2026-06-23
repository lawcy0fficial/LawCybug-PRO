package pro.lawcybug.scanner.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

/**
 * An active detector is invoked once per insertion point that Burp's
 * scanner engine (or the user, via "scan defined insertion points")
 * selects for a given base request. Implementations are free to send
 * additional HTTP requests via ctx.api().http().sendRequest(...) and/or
 * via insertionPoint.buildHttpRequestWithPayload(...).
 */
public interface ActiveDetector {

    String id();

    String displayName();

    String description();

    /**
     * Which OWASP-style category this belongs to, purely for grouping
     * in the Settings UI (e.g. "Injection", "Access Control").
     */
    String category();

    List<AuditIssue> analyze(DetectorContext ctx,
                              HttpRequestResponse baseRequestResponse,
                              AuditInsertionPoint insertionPoint);
}
