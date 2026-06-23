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
import pro.lawcybug.scanner.util.ResponseDiff;

import java.util.ArrayList;
import java.util.List;

/**
 * Boolean-based blind SQL injection: for each true/false payload pair,
 * compare the TRUE-condition response, the FALSE-condition response,
 * and the original baseline. We only report when:
 *   - TRUE response is highly similar to baseline, AND
 *   - FALSE response is meaningfully different from BOTH baseline and TRUE.
 * Requiring a three-way split (not just "the two payloads differ") is
 * what keeps this from false-positiving on pages with any per-request
 * dynamic content.
 */
public final class SqlBooleanBasedDetector implements ActiveDetector {

    public static final String ID = "sqli.boolean_blind";
    private static final double SIMILAR_THRESHOLD = 0.97;
    private static final double DIFFERENT_THRESHOLD = 0.90;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "SQL Injection - Boolean Blind";
    }

    @Override
    public String description() {
        return "Submits TRUE/FALSE condition payload pairs and looks for a consistent three-way response split versus baseline.";
    }

    @Override
    public String category() {
        return "Injection";
    }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.response() == null) {
            return issues;
        }

        for (String[] pair : SqlPayloads.BOOLEAN_PAIRS) {
            String truePayload = pair[0];
            String falsePayload = pair[1];

            HttpRequestResponse trueResult = ctx.api().http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(truePayload)));
            HttpRequestResponse falseResult = ctx.api().http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(falsePayload)));

            if (trueResult.response() == null || falseResult.response() == null) {
                continue;
            }

            double trueVsBaseline = ResponseDiff.similarity(base.response(), trueResult.response());
            double falseVsBaseline = ResponseDiff.similarity(base.response(), falseResult.response());
            double trueVsFalse = ResponseDiff.similarity(trueResult.response(), falseResult.response());

            boolean trueLooksLikeBaseline = trueVsBaseline >= SIMILAR_THRESHOLD;
            boolean falseDivergesFromBoth = falseVsBaseline < DIFFERENT_THRESHOLD && trueVsFalse < DIFFERENT_THRESHOLD;
            boolean statusDiffers = ResponseDiff.statusCodeDiffers(trueResult.response(), falseResult.response());

            if (trueLooksLikeBaseline && (falseDivergesFromBoth || statusDiffers)) {
                String detail =
                        IssueFactory.evidenceParagraph("Insertion point", insertionPoint.name())
                                + IssueFactory.evidenceParagraph("TRUE-condition payload", truePayload)
                                + IssueFactory.evidenceParagraph("FALSE-condition payload", falsePayload)
                                + IssueFactory.evidenceParagraph("Similarity (TRUE vs baseline)", String.format("%.3f", trueVsBaseline))
                                + IssueFactory.evidenceParagraph("Similarity (FALSE vs baseline)", String.format("%.3f", falseVsBaseline))
                                + IssueFactory.evidenceParagraph("Status code TRUE/FALSE", trueResult.response().statusCode() + " / " + falseResult.response().statusCode());

                issues.add(IssueFactory.build(
                        "SQL Injection (Boolean-Based Blind)",
                        detail,
                        "Use parameterized queries / prepared statements for all database access. "
                                + "Ensure error handling does not leak distinguishable TRUE/FALSE application "
                                + "states for malformed input.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.TENTATIVE,
                        "Submitting a syntactically TRUE condition produced a response nearly "
                                + "identical to baseline, while a syntactically FALSE condition (same "
                                + "structure, different logic) produced a clearly different response. "
                                + "This pattern is the standard signature of boolean-based blind SQL "
                                + "injection. Confidence is TENTATIVE because differential response "
                                + "analysis can occasionally be triggered by non-SQL input validation "
                                + "logic -- manually confirm with Repeater before reporting.",
                        trueResult, falseResult
                ));
            }
        }
        return issues;
    }
}
