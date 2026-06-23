package pro.lawcybug.scanner.detectors.bola;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.PassiveDetector;
import pro.lawcybug.scanner.workflow.ObjectGraph;
import pro.lawcybug.scanner.workflow.ResponseSimilarityEngine;
import pro.lawcybug.scanner.workflow.SessionIdentity;

import java.util.ArrayList;
import java.util.List;

/**
 * Automatic multi-user BOLA/IDOR engine, replacing the old single-header
 * "secondarySessionHeaderValue" approach with full object-graph-driven
 * cross-identity testing:
 *
 *   1. PASSIVE facet: every request Burp observes feeds the shared
 *      {@link ObjectGraph} (URL -> resourceType/id), at zero extra cost
 *      and with zero extra requests.
 *
 *   2. ACTIVE facet: for a request that references object X, this detector
 *      (a) replays the SAME request as the configured Attacker identity --
 *          classic vertical/horizontal BOLA if it succeeds where it
 *          shouldn't, and (b) replays the request swapped to a SIBLING
 *          object ID seen elsewhere on this host (from the object graph,
 *          or a numeric neighbour guess) under the Attacker identity --
 *          catching BOLA even when the attacker never legitimately owns
 *          ANY object of that type to compare against.
 *
 * Findings are only raised when the structural similarity engine confirms
 * "same response shape, different owner's data" rather than just "got a
 * 200" -- this is what keeps the false-positive rate sane.
 */
public final class CrossIdentityBolaDetector implements PassiveDetector, ActiveDetector {

    private static final String ID = "bola-cross-identity";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Cross-Identity BOLA / Object Discovery";
    }

    @Override
    public String description() {
        return "Builds an object graph from observed traffic and automatically replays "
                + "object-referencing requests under a configured Attacker identity, against "
                + "both the original object and sibling objects, to find BOLA/IDOR.";
    }

    @Override
    public String category() {
        return "Access Control / BOLA";
    }

    // ---------------------------------------------------------------
    // Passive: zero-cost object graph construction.
    // ---------------------------------------------------------------
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse rr) {
        try {
            String host = rr.request().httpService().host();
            String path = rr.request().path();
            String body = rr.response() != null ? rr.response().bodyToString() : null;
            ctx.objectGraph().observe(host, path, body);
        } catch (Exception ignored) {
        }
        return List.of();
    }

    // ---------------------------------------------------------------
    // Active: cross-identity + sibling-object replay.
    // ---------------------------------------------------------------
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse baseRequestResponse,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        if (!ctx.identityRegistry().hasMultiUserSetup()) {
            // No Victim+Attacker identities configured -- this engine has nothing
            // to test against. (Configured in the Identities tab; see README.)
            return issues;
        }

        HttpRequest base = baseRequestResponse.request();
        String host = base.httpService().host();
        String path = base.path();

        ObjectGraph.ObjectRef ref = ctx.objectGraph().extractRef(host, path);
        if (ref == null) {
            return issues; // this request doesn't reference an identifiable object
        }

        SessionIdentity attacker = ctx.identityRegistry().byRole(SessionIdentity.Role.ATTACKER).orElse(null);
        SessionIdentity victim = ctx.identityRegistry().byRole(SessionIdentity.Role.VICTIM).orElse(null);
        if (attacker == null) {
            return issues;
        }

        // Baseline: what does the ORIGINAL request return, as whichever identity
        // legitimately issued it (the original requester is implicit in base's headers)?
        int baselineStatus = baseRequestResponse.response() != null
                ? baseRequestResponse.response().statusCode() : -1;
        String baselineBody = baseRequestResponse.response() != null
                ? baseRequestResponse.response().bodyToString() : "";

        // Test 1: replay the exact same object reference as Attacker.
        replayAndEvaluate(ctx, base, attacker, ref, baselineStatus, baselineBody,
                "Same Object, Attacker Identity", issues);

        // Test 2: replay against a sibling object ID (seen elsewhere in traffic)
        // as Attacker -- catches BOLA even with no legitimate baseline to compare.
        List<String> siblings = ctx.objectGraph().siblingIds(host, ref.resourceType, ref.id);
        if (siblings.isEmpty()) {
            siblings = ctx.objectGraph().guessNeighbourIds(ref.id, 3);
        }
        for (String siblingId : siblings.subList(0, Math.min(2, siblings.size()))) {
            String swappedPath = path.replaceFirst(java.util.regex.Pattern.quote(ref.id), siblingId);
            HttpRequest swapped = base.withPath(swappedPath);
            replayAndEvaluate(ctx, swapped, attacker, ref, baselineStatus, baselineBody,
                    "Sibling Object id=" + siblingId + ", Attacker Identity", issues);
        }

        return issues;
    }

    private void replayAndEvaluate(DetectorContext ctx, HttpRequest request, SessionIdentity identity,
                                    ObjectGraph.ObjectRef ref, int baselineStatus, String baselineBody,
                                    String scenarioLabel, List<AuditIssue> issues) {
        try {
            HttpRequest stamped = identity.stamp(request);
            HttpRequestResponse result = ctx.api().http().sendRequest(stamped);
            if (result.response() == null) return;

            int status = result.response().statusCode();
            String body = result.response().bodyToString();

            if (status < 200 || status >= 300) {
                return; // properly rejected (401/403/404) -- not a finding
            }

            ResponseSimilarityEngine.Verdict verdict =
                    ctx.similarityEngine().compare(baselineStatus, baselineBody, status, body);

            if (verdict.looksLikeBolaSuccess) {
                issues.add(IssueFactory.build(
                        "Broken Object Level Authorization (BOLA/IDOR)",
                        "<p>Replaying a request for <code>" + IssueFactory.escapeHtml(ref.resourceType)
                                + "</code> object id <code>" + IssueFactory.escapeHtml(ref.id)
                                + "</code> under the configured <b>Attacker</b> identity ("
                                + IssueFactory.escapeHtml(scenarioLabel) + ") returned HTTP " + status
                                + " with a response that is structurally identical to a legitimate response "
                                + "(key-overlap ratio " + String.format("%.2f", verdict.keyOverlapRatio)
                                + "), but with different data values -- the classic signature of a "
                                + "successful authorization bypass rather than a coincidental shape match.</p>"
                                + IssueFactory.evidenceParagraph("Endpoint", request.url())
                                + IssueFactory.evidenceParagraph("Resource", ref.resourceType + "/" + ref.id)
                                + IssueFactory.evidenceParagraph("Scenario", scenarioLabel)
                                + IssueFactory.evidenceParagraph("Differing fields",
                                String.join(", ", verdict.differingKeys)),
                        "<p>Enforce object-level authorization checks server-side on every request that "
                                + "accepts an object identifier: verify the authenticated identity actually "
                                + "owns/has-been-granted-access-to that specific object instance, not merely "
                                + "that they are authenticated at all.</p>",
                        request.url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "<p>BOLA (Broken Object Level Authorization, OWASP API1:2023) occurs when an API "
                                + "checks that a caller is authenticated but not that they're authorized for "
                                + "the SPECIFIC object instance referenced in the request.</p>",
                        result
                ));
            }
        } catch (Exception ignored) {
        }
    }
}
