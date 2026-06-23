package pro.lawcybug.scanner.detectors.atochain;

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
import pro.lawcybug.scanner.workflow.SessionIdentity;
import pro.lawcybug.scanner.workflow.WorkflowEngine;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Privilege-escalation CHAIN detector: rather than just probing a single
 * request body for an injected "role":"admin" field (which is what the
 * existing single-request MassAssignmentConfirmDetector does), this runs a
 * two-step chain:
 *
 *   Step 1 (MUTATING -- subject to Safe Mode): replay the base request as
 *           the VICTIM identity, with extra privileged-looking fields
 *           merged into the JSON body (role/isAdmin/permissions/groups).
 *   Step 2 (read-only): immediately follow up with a profile/self-lookup
 *           request as the SAME identity to check whether the privileged
 *           value actually took effect server-side, rather than trusting
 *           an echo in Step 1's own response (which proves nothing -- many
 *           APIs echo back exactly what you sent regardless of whether it
 *           was persisted).
 *
 * This verification step is what separates a real finding from the noisy
 * "field was reflected" false positives mass-assignment checkers are
 * notorious for.
 */
public final class PrivilegeEscalationChainDetector implements ActiveDetector {

    private static final String ID = "privesc-chain";

    private static final Pattern JSON_BODY = Pattern.compile("^\\s*\\{");
    private static final String[] PRIV_FIELDS = {
            "\"role\":\"admin\"",
            "\"isAdmin\":true",
            "\"is_admin\":true",
            "\"permissions\":[\"*\"]",
            "\"roleId\":1",
            "\"groups\":[\"administrators\"]"
    };

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Privilege Escalation Chain (Mass Assignment + Verification)";
    }

    @Override
    public String description() {
        return "Injects privileged fields into a JSON request body as the Victim identity, "
                + "then independently verifies via a follow-up self-lookup request whether the "
                + "privilege change actually persisted server-side.";
    }

    @Override
    public String category() {
        return "Business Logic / Privilege Escalation";
    }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse baseRequestResponse,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        HttpRequest base = baseRequestResponse.request();
        String body = base.bodyToString();
        if (body == null || !JSON_BODY.matcher(body).find()) {
            return issues; // only meaningful against JSON-body requests
        }
        // Only run against requests that look like they touch the caller's own
        // account/profile/settings -- this is where role/permission fields are
        // most plausibly accepted, and keeps request volume sane.
        String path = base.path().toLowerCase();
        boolean plausibleTarget = path.contains("profile") || path.contains("account")
                || path.contains("user") || path.contains("settings") || path.contains("me");
        if (!plausibleTarget) {
            return issues;
        }

        SessionIdentity victim = ctx.identityRegistry().byRole(SessionIdentity.Role.VICTIM).orElse(null);
        if (victim == null) {
            return issues; // chain needs an identity to act as and re-verify under
        }

        String profileCheckPath = guessProfileCheckPath(path);
        if (profileCheckPath == null) {
            return issues;
        }

        for (String injectedField : PRIV_FIELDS) {
            String mutatedBody = injectField(body, injectedField);
            if (mutatedBody.equals(body)) continue;

            List<WorkflowEngine.Step> steps = new ArrayList<>();
            steps.add(new WorkflowEngine.Step("Inject privileged field",
                    vars -> base.withBody(ByteArray.byteArray(mutatedBody))).asMutating());
            steps.add(new WorkflowEngine.Step("Verify via self-lookup",
                    vars -> base.withMethod("GET").withPath(profileCheckPath).withBody(ByteArray.byteArray(""))));

            WorkflowEngine.ChainResult result = ctx.workflowEngine().run(steps, victim);
            if (result.steps.size() < 2) {
                continue; // blocked by Safe Mode, budget, or the first step failed -- nothing to report
            }

            WorkflowEngine.StepResult verify = result.steps.get(1);
            if (!verify.succeeded || verify.requestResponse.response() == null) continue;

            String verifyBody = verify.requestResponse.response().bodyToString();
            if (confirmsEscalation(injectedField, verifyBody)) {
                issues.add(IssueFactory.build(
                        "Privilege Escalation via Mass Assignment (Verified)",
                        "<p>Injecting <code>" + IssueFactory.escapeHtml(injectedField)
                                + "</code> into this endpoint's JSON body as the configured Victim identity, "
                                + "followed by an independent self-lookup request, confirms the privileged "
                                + "value was actually PERSISTED server-side -- not merely echoed back.</p>"
                                + IssueFactory.evidenceParagraph("Endpoint", base.url())
                                + IssueFactory.evidenceParagraph("Injected field", injectedField)
                                + IssueFactory.evidenceParagraph("Verification endpoint", profileCheckPath),
                        "<p>Use an explicit allow-list of bindable fields on every write endpoint "
                                + "(DTO/serializer-level field whitelisting) rather than binding the full "
                                + "request body to an internal model. Role/permission fields should never "
                                + "be settable through user-facing profile/account update endpoints.</p>",
                        base.url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "<p>Mass assignment vulnerabilities occur when frameworks auto-bind request bodies "
                                + "directly onto internal models without field-level restriction.</p>",
                        result.steps.get(0).requestResponse,
                        verify.requestResponse
                ));
                break; // one confirmed escalation is enough; no need to keep trying every field
            }
        }

        return issues;
    }

    private String injectField(String jsonBody, String fieldKeyValue) {
        int idx = jsonBody.indexOf('{');
        if (idx == -1) return jsonBody;
        return jsonBody.substring(0, idx + 1) + fieldKeyValue + ","
                + jsonBody.substring(idx + 1);
    }

    private String guessProfileCheckPath(String mutationPath) {
        // Heuristic: most "update profile" endpoints have a sibling read-only
        // GET at the same path, or a conventional /me or /profile path.
        if (mutationPath.endsWith("/")) mutationPath = mutationPath.substring(0, mutationPath.length() - 1);
        return mutationPath; // same path, different method (GET) -- handled by the step builder above
    }

    private boolean confirmsEscalation(String injectedField, String verifyBody) {
        if (verifyBody == null) return false;
        if (injectedField.contains("\"role\":\"admin\"")) {
            return Pattern.compile("\"role\"\\s*:\\s*\"admin\"", Pattern.CASE_INSENSITIVE).matcher(verifyBody).find();
        }
        if (injectedField.contains("isAdmin") || injectedField.contains("is_admin")) {
            return Pattern.compile("\"is_?[Aa]dmin\"\\s*:\\s*true").matcher(verifyBody).find();
        }
        if (injectedField.contains("permissions")) {
            return verifyBody.contains("\"permissions\"") && verifyBody.contains("*");
        }
        if (injectedField.contains("roleId")) {
            return Pattern.compile("\"roleId\"\\s*:\\s*1\\b").matcher(verifyBody).find();
        }
        if (injectedField.contains("administrators")) {
            return verifyBody.contains("administrators");
        }
        return false;
    }
}
