package pro.lawcybug.scanner.core;

import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;

/**
 * Every detector should build its AuditIssue through this helper so that
 * naming, HTML escaping discipline and evidence formatting stay consistent
 * across the whole extension, regardless of which engineer (or which of
 * the 30+ detector classes) produced the issue.
 *
 * Note: Burp HTML-whitelists issue text (only basic formatting + simple
 * hyperlinks survive), so we deliberately keep markup minimal here.
 */
public final class IssueFactory {

    private IssueFactory() {
    }

    public static AuditIssue build(String name,
                                    String detailHtml,
                                    String remediationHtml,
                                    String baseUrl,
                                    AuditIssueSeverity severity,
                                    AuditIssueConfidence confidence,
                                    String backgroundHtml,
                                    HttpRequestResponse... evidence) {
        return AuditIssue.auditIssue(
                "[LawCyBug.pro] " + name,
                detailHtml,
                remediationHtml,
                baseUrl,
                severity,
                confidence,
                backgroundHtml,
                null,
                severity,
                evidence
        );
    }

    /**
     * Highlights a byte range in the evidence response. NOTE: start/end here are
     * offsets into the RAW response (headers + blank line + body) — exactly what
     * Burp's Marker expects and what the request/response viewer renders against.
     * Most detectors instead have an offset found via a Matcher run against
     * response().bodyToString() (body text only); for those, use
     * {@link #withResponseBodyHighlight} below instead of calling this directly,
     * or the highlight will land somewhere in the headers instead of on the match.
     */
    public static HttpRequestResponse withResponseHighlight(HttpRequestResponse requestResponse,
                                                              int start,
                                                              int end) {
        if (start < 0 || end <= start) {
            return requestResponse;
        }
        return requestResponse.withResponseMarkers(List.of(Marker.marker(start, end)));
    }

    /**
     * Highlights a byte range within the RESPONSE BODY (e.g. start/end from a
     * Matcher run against response().bodyToString()). Converts to the raw
     * full-response offset Marker actually needs by adding bodyOffset() —
     * use this any time your start/end came from a body-only string, which is
     * almost always the case.
     */
    public static HttpRequestResponse withResponseBodyHighlight(HttpRequestResponse requestResponse,
                                                                  int bodyStart,
                                                                  int bodyEnd) {
        if (requestResponse.response() == null || bodyStart < 0 || bodyEnd <= bodyStart) {
            return requestResponse;
        }
        int offset = requestResponse.response().bodyOffset();
        return withResponseHighlight(requestResponse, offset + bodyStart, offset + bodyEnd);
    }

    public static HttpRequestResponse withRequestHighlight(HttpRequestResponse requestResponse,
                                                             int start,
                                                             int end) {
        if (start < 0 || end <= start) {
            return requestResponse;
        }
        return requestResponse.withRequestMarkers(List.of(Marker.marker(start, end)));
    }

    public static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    public static String evidenceParagraph(String label, String value) {
        return "<p><b>" + escapeHtml(label) + ":</b> " + escapeHtml(value) + "</p>";
    }
}
