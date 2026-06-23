package pro.lawcybug.scanner.core;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * UI-facing wrapper around an AuditIssue, with a timestamp and the
 * id of the detector that raised it. Burp's own AuditIssue is the
 * source of truth (it's what shows up in the Burp "Issues" / "Dashboard"
 * UI); this wrapper exists purely so our own Suite tab can show a live,
 * scrollable feed without re-querying Burp's site map constantly.
 */
public final class Finding {

    public enum Status {
        NEW("New"), REVIEWED("Reviewed"), FALSE_POSITIVE("False Positive");

        public final String label;
        Status(String label) { this.label = label; }
    }

    private static final DateTimeFormatter TS_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final String detectorId;
    private final AuditIssue issue;
    private final LocalDateTime timestamp;
    private volatile Status status = Status.NEW;

    public Finding(String detectorId, AuditIssue issue) {
        this.detectorId = detectorId;
        this.issue = issue;
        this.timestamp = LocalDateTime.now();
    }

    public String detectorId() {
        return detectorId;
    }

    public AuditIssue issue() {
        return issue;
    }

    public Status status() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public String formattedTime() {
        return timestamp.format(TS_FORMAT);
    }

    public LocalDateTime timestamp() {
        return timestamp;
    }
}
