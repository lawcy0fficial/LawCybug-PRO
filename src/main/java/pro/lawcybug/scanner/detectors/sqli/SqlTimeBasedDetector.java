package pro.lawcybug.scanner.detectors.sqli;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.ScanSettings;
import pro.lawcybug.scanner.util.TimingUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Time-based blind SQL injection across MySQL, MSSQL, PostgreSQL and
 * Oracle delay primitives, confirmed via repeated-measurement statistics
 * (see TimingUtils) rather than a single slow response, to keep the
 * false-positive rate low on naturally slow or rate-limited endpoints.
 */
public final class SqlTimeBasedDetector implements ActiveDetector {

    public static final String ID = "sqli.time_blind";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "SQL Injection - Time-Based Blind";
    }

    @Override
    public String description() {
        return "Statistically-confirmed time-delay payloads across MySQL/MSSQL/PostgreSQL/Oracle.";
    }

    @Override
    public String category() {
        return "Injection";
    }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        ScanSettings settings = ctx.settings();
        int repeats = settings.getTimeBasedRequestRepeats();
        long delaySeconds = settings.getTimeBasedDelaySeconds();

        String[] payloads = SqlPayloads.timeDelayPayloads(delaySeconds);
        if (settings.getIntensity() == ScanSettings.Intensity.QUICK) {
            payloads = new String[]{payloads[0], payloads[4], payloads[6]}; // one per major engine
        }

        // Baseline: original request repeated, NOT modified (uses the base
        // request as-is so we measure this endpoint's normal latency floor).
        TimingUtils.TimingResult baseline = TimingUtils.measure(ctx.api().http(), base.request(), repeats);

        for (String payload : payloads) {
            HttpRequest delayedRequest = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
            TimingUtils.TimingResult delayed = TimingUtils.measure(ctx.api().http(), delayedRequest, repeats);

            if (TimingUtils.isConvincingDelay(baseline, delayed, delaySeconds)) {
                HttpRequestResponse evidence = ctx.api().http().sendRequest(delayedRequest);

                String detail =
                        IssueFactory.evidenceParagraph("Insertion point", insertionPoint.name())
                                + IssueFactory.evidenceParagraph("Payload", payload)
                                + IssueFactory.evidenceParagraph("Requested delay", delaySeconds + "s")
                                + IssueFactory.evidenceParagraph("Baseline timings (ms)", baseline.millis.toString())
                                + IssueFactory.evidenceParagraph("Delayed timings (ms)", delayed.millis.toString());

                issues.add(IssueFactory.build(
                        "SQL Injection (Time-Based Blind)",
                        detail,
                        "Use parameterized queries / prepared statements for all database access. "
                                + "Validate and strictly type input that reaches database queries.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "A SQL time-delay payload (" + delaySeconds + "s) was submitted " + repeats
                                + " times in the '" + insertionPoint.name() + "' parameter. Every "
                                + "measurement clearly exceeded both the baseline latency for this "
                                + "endpoint and the expected delay threshold, which is strong evidence "
                                + "the payload reached and executed inside a SQL statement.",
                        evidence
                ));
                // One confirmed engine is enough for this insertion point.
                break;
            }
        }
        return issues;
    }
}
