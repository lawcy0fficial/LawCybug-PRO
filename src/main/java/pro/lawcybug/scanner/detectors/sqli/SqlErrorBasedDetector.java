package pro.lawcybug.scanner.detectors.sqli;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.ScanSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Classic error-based SQL injection: insert a syntax-breaking probe,
 * look for a recognizable database error signature in the response
 * that was NOT present in the baseline (so we don't false-positive on
 * pages that always mention "SQL" or "syntax", e.g. documentation).
 */
public final class SqlErrorBasedDetector implements ActiveDetector {

    public static final String ID = "sqli.error_based";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "SQL Injection - Error Based";
    }

    @Override
    public String description() {
        return "Inserts syntax-breaking probes and checks for database error signatures absent from the baseline response.";
    }

    @Override
    public String category() {
        return "Injection";
    }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        String baselineBody = base.response() != null ? base.response().bodyToString() : "";

        List<String> probes = SqlPayloads.ERROR_PROBES;
        if (ctx.settings().getIntensity() == ScanSettings.Intensity.QUICK) {
            probes = probes.subList(0, Math.min(3, probes.size()));
        }

        for (String probe : probes) {
            HttpRequestResponse result = ctx.api().http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(probe))
            );
            if (result.response() == null) {
                continue;
            }
            String body = result.response().bodyToString();

            for (Object[] sig : signatures()) {
                java.util.regex.Pattern pattern = (java.util.regex.Pattern) sig[0];
                String engine = (String) sig[1];

                Matcher matcher = pattern.matcher(body);
                if (matcher.find() && !pattern.matcher(baselineBody).find()) {
                    int start = matcher.start();
                    int end = matcher.end();
                    HttpRequestResponse highlighted = IssueFactory.withResponseBodyHighlight(result, start, end);

                    String detail =
                            IssueFactory.evidenceParagraph("Insertion point", insertionPoint.name())
                                    + IssueFactory.evidenceParagraph("Payload", probe)
                                    + IssueFactory.evidenceParagraph("Detected engine", engine)
                                    + IssueFactory.evidenceParagraph("Matched signature", matcher.group());

                    issues.add(IssueFactory.build(
                            "SQL Injection (Error-Based) - " + engine,
                            detail,
                            "Use parameterized queries / prepared statements for all database access. "
                                    + "Never concatenate user-controllable input into SQL strings. "
                                    + "Apply least-privilege database accounts and suppress verbose database "
                                    + "error messages in production responses.",
                            base.request().url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.FIRM,
                            "A database error message was returned after submitting a SQL "
                                    + "metacharacter probe in the '" + insertionPoint.name()
                                    + "' parameter, and the same error message was not present in the "
                                    + "baseline (unmodified) response. This strongly suggests user input "
                                    + "is being concatenated directly into a SQL query.",
                            highlighted
                    ));
                    // One confirmed signature per probe is enough; move to next probe.
                    break;
                }
            }
        }
        return issues;
    }

    private List<Object[]> signatures() {
        return SqlPayloads.ERROR_SIGNATURES;
    }
}
