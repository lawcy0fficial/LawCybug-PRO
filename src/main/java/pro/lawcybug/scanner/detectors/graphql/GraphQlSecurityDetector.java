package pro.lawcybug.scanner.detectors.graphql;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.PassiveDetector;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GraphQL-aware security checks. Registered as BOTH a passive detector
 * (endpoint fingerprinting + introspection-already-exposed detection on
 * traffic Burp has already seen) and an active detector (sends crafted
 * GraphQL probes once a GraphQL endpoint has been confirmed).
 *
 * Covers, at a useful confidence level for bug bounty triage:
 *   1. Introspection enabled in environments that look production-like
 *   2. Batching / array-of-queries DoS and auth-bypass surface
 *   3. Field duplication / aliasing amplification (cheap query-cost bypass)
 *   4. Excessive query depth accepted without limit
 *   5. Suggestion/"did you mean" field leakage when introspection is off
 *   6. GET-based GraphQL (CSRF surface) and missing content-type checks
 */
public final class GraphQlSecurityDetector implements PassiveDetector, ActiveDetector {

    private static final String ID = "graphql-security";

    // Cheap heuristics for "this request/response is GraphQL".
    private static final Pattern GQL_BODY_HINT =
            Pattern.compile("\"(query|mutation|operationName)\"\\s*:", Pattern.CASE_INSENSITIVE);
    private static final Pattern GQL_KEYWORD_HINT =
            Pattern.compile("\\b(query|mutation|subscription)\\s*[\\w]*\\s*\\{", Pattern.CASE_INSENSITIVE);
    private static final Pattern DID_YOU_MEAN =
            Pattern.compile("did you mean", Pattern.CASE_INSENSITIVE);
    private static final Pattern TYPENAME_LEAK =
            Pattern.compile("\"__typename\"\\s*:\\s*\"([A-Za-z0-9_]+)\"");

    private static final String INTROSPECTION_PROBE = "{\"query\":\"query LCBIntrospect{__schema{queryType{name}"
            + "types{name kind fields{name}}}}\"}";

    private static final String DEPTH_BOMB_PROBE = buildDepthBomb(12);

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "GraphQL Security Suite";
    }

    @Override
    public String description() {
        return "Detects exposed introspection, batching/aliasing cost-bypass, "
                + "unbounded query depth, and field-suggestion leakage on GraphQL endpoints.";
    }

    @Override
    public String category() {
        return "API Security / GraphQL";
    }

    // ---------------------------------------------------------------
    // Passive: only looks at traffic already captured, never fires a request.
    // ---------------------------------------------------------------
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse rr) {
        List<AuditIssue> issues = new ArrayList<>();
        if (rr.response() == null) {
            return issues;
        }
        if (!looksLikeGraphQl(rr.request(), rr.response())) {
            return issues;
        }

        String body = rr.response().bodyToString();

        // Feed the shared object graph: GraphQL responses are JSON with "id"/
        // "__typename" fields in the exact shape ObjectGraph already parses,
        // so the same cross-identity BOLA engine built for REST applies here too.
        try {
            ctx.objectGraph().observe(rr.request().httpService().host(), rr.request().path(), body);
        } catch (Exception ignored) {
        }


        // 1. Introspection result already present in a captured response.
        if (body.contains("__schema") && body.contains("queryType")) {
            issues.add(IssueFactory.build(
                    "GraphQL Introspection Exposed",
                    "<p>A GraphQL response observed in traffic contains a live <code>__schema</code> "
                            + "introspection result. Introspection lets an attacker enumerate the entire "
                            + "API surface (types, mutations, hidden/internal fields) without any prior knowledge.</p>"
                            + IssueFactory.evidenceParagraph("Endpoint", rr.request().url()),
                    "<p>Disable introspection in production (e.g. <code>NoSchemaIntrospectionCustomRule</code> "
                            + "in graphql-java, or the equivalent for your GraphQL server), or gate it behind "
                            + "authenticated/internal-only access.</p>",
                    rr.request().url(),
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.CERTAIN,
                    "<p>GraphQL introspection is a built-in schema-discovery feature meant for development tooling.</p>",
                    rr
            ));
        }

        // 2. Field suggestion leakage even when introspection itself is disabled.
        Matcher dym = DID_YOU_MEAN.matcher(body);
        if (dym.find()) {
            issues.add(IssueFactory.build(
                    "GraphQL Field Suggestion Leakage",
                    "<p>The GraphQL server returns \"did you mean\" field-suggestion errors. This lets an "
                            + "attacker reconstruct the schema field-by-field even when introspection is disabled, "
                            + "via repeated typo'd queries.</p>"
                            + IssueFactory.evidenceParagraph("Endpoint", rr.request().url()),
                    "<p>Disable suggestion hints in error responses for non-development environments "
                            + "(in graphql-java: a custom <code>GraphQLError</code> formatter that strips suggestions).</p>",
                    rr.request().url(),
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.FIRM,
                    null,
                    rr
            ));
        }

        // 3. GraphQL served over GET with a simple content-type -> CSRF surface.
        String method = rr.request().method();
        if ("GET".equalsIgnoreCase(method) && rr.request().url().contains("query=")) {
            issues.add(IssueFactory.build(
                    "GraphQL over GET (Potential CSRF Surface)",
                    "<p>This GraphQL operation was executed via a GET request with the query in the URL. "
                            + "If the server doesn't separately enforce CSRF tokens or strict "
                            + "<code>Content-Type: application/json</code>-only POST handling, state-changing "
                            + "mutations may be triggerable cross-site (e.g. via a crafted &lt;img&gt; or link).</p>"
                            + IssueFactory.evidenceParagraph("URL", rr.request().url()),
                    "<p>Restrict GraphQL execution to POST with <code>Content-Type: application/json</code>, "
                            + "and verify mutations are not reachable via simple cross-site GET/POST forms.</p>",
                    rr.request().url(),
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.TENTATIVE,
                    null,
                    rr
            ));
        }

        return issues;
    }

    // ---------------------------------------------------------------
    // Active: fires crafted probes once we believe this insertion point
    // sits on a GraphQL endpoint (base request already looks like GraphQL).
    // ---------------------------------------------------------------
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse baseRequestResponse,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpRequest base = baseRequestResponse.request();
        if (!looksLikeGraphQl(base, baseRequestResponse.response())) {
            return issues;
        }

        // Only probe once per base request, not once per insertion point,
        // to avoid hammering the endpoint with N copies of the same probes.
        if (!insertionPoint.name().isEmpty() && !isPrimaryInsertionPoint(insertionPoint)) {
            return issues;
        }

        probeIntrospection(ctx, base, issues);
        probeBatching(ctx, base, issues);
        probeDepthBomb(ctx, base, issues);
        probeAliasAbuse(ctx, base, issues);
        probeMutationEnumeration(ctx, base, issues);

        return issues;
    }

    private boolean isPrimaryInsertionPoint(AuditInsertionPoint insertionPoint) {
        // Heuristic: only act on the body insertion point if present, otherwise
        // accept whatever the first offered insertion point is. This keeps the
        // 3 active probes from firing once per parameter on a GraphQL request
        // that may have many JSON fields tagged as separate insertion points.
        String name = insertionPoint.name();
        return name.equalsIgnoreCase("query")
                || name.equalsIgnoreCase("json")
                || name.isBlank();
    }

    private void probeIntrospection(DetectorContext ctx, HttpRequest base, List<AuditIssue> issues) {
        try {
            HttpRequest probe = base.withBody(ByteArray.byteArray(INTROSPECTION_PROBE))
                    .withUpdatedHeader("Content-Type", "application/json");
            HttpRequestResponse result = ctx.api().http().sendRequest(probe);
            if (result.response() == null) return;
            String body = result.response().bodyToString();
            if (body.contains("\"queryType\"") && body.contains("\"types\"")) {
                issues.add(IssueFactory.build(
                        "GraphQL Introspection Enabled (Active Probe)",
                        "<p>Sending a minimal <code>__schema</code> introspection query to this endpoint "
                                + "returned a full schema enumeration, confirming introspection is enabled.</p>"
                                + IssueFactory.evidenceParagraph("Endpoint", base.url())
                                + IssueFactory.evidenceParagraph("Probe", INTROSPECTION_PROBE),
                        "<p>Disable introspection outside development environments.</p>",
                        base.url(),
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        result
                ));
            }
        } catch (Exception ignored) {
            // Defensive: a malformed probe against a non-conforming server should
            // never take down the rest of the scan.
        }
    }

    private void probeBatching(DetectorContext ctx, HttpRequest base, List<AuditIssue> issues) {
        try {
            // Array-of-operations batching: many GraphQL servers (esp. Apollo)
            // accept a JSON array body as a batch of independent operations.
            // If accepted, this is a known vector for brute-force/rate-limit
            // bypass (N guesses in a single HTTP request) and resolver-level
            // auth bypass when batch items aren't individually authorized.
            String batch = "[" + "{\"query\":\"{__typename}\"},".repeat(5) + "{\"query\":\"{__typename}\"}]";
            HttpRequest probe = base.withBody(ByteArray.byteArray(batch))
                    .withUpdatedHeader("Content-Type", "application/json");
            HttpRequestResponse result = ctx.api().http().sendRequest(probe);
            if (result.response() == null) return;
            String body = result.response().bodyToString();
            int typenameCount = countOccurrences(body, "__typename");
            if (result.response().statusCode() == 200 && typenameCount >= 6) {
                issues.add(IssueFactory.build(
                        "GraphQL Batched Query Operations Accepted",
                        "<p>The endpoint accepted a JSON array of 6 independent GraphQL operations in a single "
                                + "HTTP request and executed all of them. Batching is commonly abused to bypass "
                                + "per-request rate limiting (e.g. brute-forcing OTPs/passwords/coupon codes in "
                                + "bulk) and can expose resolver-level authorization gaps if mutations in the "
                                + "batch aren't each independently checked.</p>"
                                + IssueFactory.evidenceParagraph("Endpoint", base.url())
                                + IssueFactory.evidenceParagraph("Matched operations in response",
                                String.valueOf(typenameCount)),
                        "<p>Disable array-batching if not required by the frontend, or enforce per-operation "
                                + "rate-limiting and authorization checks within batched requests, and cap "
                                + "batch size server-side.</p>",
                        base.url(),
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.FIRM,
                        null,
                        result
                ));
            }
        } catch (Exception ignored) {
        }
    }

    private void probeDepthBomb(DetectorContext ctx, HttpRequest base, List<AuditIssue> issues) {
        try {
            HttpRequest probe = base.withBody(ByteArray.byteArray(DEPTH_BOMB_PROBE))
                    .withUpdatedHeader("Content-Type", "application/json");
            long start = System.nanoTime();
            HttpRequestResponse result = ctx.api().http().sendRequest(probe);
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            if (result.response() == null) return;

            boolean rejectedCleanly = result.response().statusCode() == 400
                    && result.response().bodyToString().toLowerCase().contains("depth");

            if (!rejectedCleanly && result.response().statusCode() == 200) {
                AuditIssueSeverity severity = elapsedMs > 3000
                        ? AuditIssueSeverity.HIGH
                        : AuditIssueSeverity.LOW;
                issues.add(IssueFactory.build(
                        "GraphQL Query Depth Not Limited (Potential DoS)",
                        "<p>A deeply nested (12-level) self-referencing query was accepted and returned HTTP 200 "
                                + "rather than being rejected for exceeding a depth limit. Unbounded query depth "
                                + "combined with circular/self-referencing schema relationships is a classic "
                                + "GraphQL resource-exhaustion (DoS) vector.</p>"
                                + IssueFactory.evidenceParagraph("Endpoint", base.url())
                                + IssueFactory.evidenceParagraph("Response time", elapsedMs + " ms"),
                        "<p>Enforce a maximum query depth and/or computed query-cost limit server-side "
                                + "(e.g. graphql-depth-limit, or a cost-analysis library appropriate to your stack).</p>",
                        base.url(),
                        severity,
                        AuditIssueConfidence.TENTATIVE,
                        "<p>Without depth limiting, a self-referencing schema (e.g. user { friends { user "
                                + "{ friends { ... } } } }) lets a single small request expand into an "
                                + "exponential amount of backend work.</p>",
                        result
                ));
            }
        } catch (Exception ignored) {
        }
    }

    private void probeAliasAbuse(DetectorContext ctx, HttpRequest base, List<AuditIssue> issues) {
        try {
            // Aliasing abuse: unlike array-batching (probeBatching, multiple JSON
            // objects), this packs N copies of the SAME field into ONE query
            // object under distinct aliases, e.g. { a0: __typename a1: __typename
            // ... a49: __typename }. Many cost-limiting implementations only
            // count distinct field selections, not aliased repeats, so this
            // bypasses naive query-cost limits even when batching itself is
            // disabled or capped.
            StringBuilder aliased = new StringBuilder("query LCBAlias{");
            int aliasCount = 50;
            for (int i = 0; i < aliasCount; i++) {
                aliased.append("a").append(i).append(":__typename ");
            }
            aliased.append("}");
            String probeBody = "{\"query\":\"" + aliased.toString().replace("\"", "\\\"") + "\"}";

            HttpRequest probe = base.withBody(ByteArray.byteArray(probeBody))
                    .withUpdatedHeader("Content-Type", "application/json");
            long start = System.nanoTime();
            HttpRequestResponse result = ctx.api().http().sendRequest(probe);
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            if (result.response() == null) return;

            String respBody = result.response().bodyToString();
            int aliasHits = countOccurrences(respBody, "\"a") ; // crude but cheap: a0":..","a1":...
            boolean rejected = result.response().statusCode() == 400
                    && respBody.toLowerCase().contains("complexity");

            if (!rejected && result.response().statusCode() == 200 && aliasHits >= aliasCount / 2) {
                issues.add(IssueFactory.build(
                        "GraphQL Alias-Based Query Cost Bypass",
                        "<p>A single query requesting the same field " + aliasCount + " times under distinct "
                                + "aliases was accepted and executed (HTTP 200, response in " + elapsedMs + " ms) "
                                + "rather than being rejected for excessive query cost. Cost-limiting "
                                + "implementations that count distinct field selections rather than aliased "
                                + "repeats are bypassed by this technique, which can be combined with a "
                                + "moderately expensive field (instead of the cheap <code>__typename</code> "
                                + "used here) for real resource-exhaustion impact.</p>"
                                + IssueFactory.evidenceParagraph("Endpoint", base.url())
                                + IssueFactory.evidenceParagraph("Aliases requested", String.valueOf(aliasCount)),
                        "<p>Compute query cost based on the actual number of field RESOLUTIONS (i.e. counting "
                                + "aliased repeats), not distinct field names in the query AST. Most GraphQL "
                                + "cost-analysis libraries (graphql-cost-analysis, graphql-query-complexity) "
                                + "support this when configured correctly -- verify aliasing is included.</p>",
                        base.url(),
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.TENTATIVE,
                        "<p>This probe used the harmless <code>__typename</code> field to prove the bypass "
                                + "exists without causing real load; the actual DoS risk depends on substituting "
                                + "a genuinely expensive field/resolver, which requires schema knowledge to pick.</p>",
                        result
                ));
            }
        } catch (Exception ignored) {
        }
    }

    private void probeMutationEnumeration(DetectorContext ctx, HttpRequest base, List<AuditIssue> issues) {
        try {
            String probeBody = "{\"query\":\"query LCBMutations{__schema{mutationType{fields{name "
                    + "args{name type{name kind}}}}}}\"}";
            HttpRequest probe = base.withBody(ByteArray.byteArray(probeBody))
                    .withUpdatedHeader("Content-Type", "application/json");
            HttpRequestResponse result = ctx.api().http().sendRequest(probe);
            if (result.response() == null) return;

            String body = result.response().bodyToString();
            if (!body.contains("\"mutationType\"") || body.contains("\"mutationType\":null")) {
                return;
            }

            Matcher names = Pattern.compile("\"name\"\\s*:\\s*\"([A-Za-z_][A-Za-z0-9_]*)\"").matcher(body);
            java.util.LinkedHashSet<String> mutationNames = new java.util.LinkedHashSet<>();
            while (names.find()) {
                mutationNames.add(names.group(1));
            }
            // Filter out obvious arg-type names that also match \"name\":\"...\" (e.g.
            // "String", "Int") by keeping only ones that look like camelCase verbs --
            // a heuristic, not a real type-vs-field distinction, but cuts noise a lot.
            mutationNames.removeIf(n -> n.matches("^(String|Int|Boolean|Float|ID)$"));

            // Highlight mutations whose names suggest high-impact/admin operations --
            // these are exactly the ones worth a human spending time enumerating
            // permissions on, out of what could be a list of 50+ mutations.
            List<String> sensitiveLooking = mutationNames.stream()
                    .filter(n -> n.toLowerCase().matches(".*(delete|remove|admin|grant|role|permission|"
                            + "impersonate|reset|disable|ban|suspend|transfer|refund|payout).*"))
                    .toList();

            if (!mutationNames.isEmpty()) {
                issues.add(IssueFactory.build(
                        "GraphQL Mutation Enumeration via Introspection",
                        "<p>Introspecting the mutation type on this endpoint enumerated "
                                + mutationNames.size() + " mutation(s), revealing the full set of state-changing "
                                + "operations the API exposes -- valuable attack-surface mapping regardless of "
                                + "whether each mutation is individually exploitable.</p>"
                                + (sensitiveLooking.isEmpty() ? "" :
                                "<p><b>Names suggesting high-impact/admin operations:</b> "
                                        + IssueFactory.escapeHtml(String.join(", ", sensitiveLooking)) + "</p>")
                                + IssueFactory.evidenceParagraph("Endpoint", base.url())
                                + IssueFactory.evidenceParagraph("Total mutations found", String.valueOf(mutationNames.size())),
                        "<p>This finding is a direct consequence of introspection being enabled -- see the "
                                + "separate \"GraphQL Introspection Exposed\" finding for remediation. Beyond "
                                + "disabling introspection, ensure every mutation independently enforces "
                                + "authorization regardless of whether its existence is discoverable.</p>",
                        base.url(),
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        result
                ));
            }
        } catch (Exception ignored) {
        }
    }

    // ---------------------------------------------------------------
    // Shared helpers
    // ---------------------------------------------------------------

    private boolean looksLikeGraphQl(HttpRequest request, HttpResponse response) {
        if (request != null) {
            String url = request.url().toLowerCase();
            if (url.contains("graphql") || url.contains("/gql")) {
                return true;
            }
            String reqBody = request.bodyToString();
            if (reqBody != null && (GQL_BODY_HINT.matcher(reqBody).find()
                    || GQL_KEYWORD_HINT.matcher(reqBody).find())) {
                return true;
            }
        }
        if (response != null) {
            String respBody = response.bodyToString();
            if (respBody != null && (TYPENAME_LEAK.matcher(respBody).find()
                    || respBody.contains("\"errors\":[{\"message\"") && respBody.contains("GraphQL"))) {
                return true;
            }
        }
        return false;
    }

    private static String buildDepthBomb(int depth) {
        StringBuilder inner = new StringBuilder("__typename");
        for (int i = 0; i < depth; i++) {
            inner = new StringBuilder("node{" + inner + "}");
        }
        String query = "query LCBDepth{" + inner + "}";
        return "{\"query\":\"" + query.replace("\"", "\\\"") + "\"}";
    }

    private static int countOccurrences(String haystack, String needle) {
        if (haystack == null || needle.isEmpty()) return 0;
        int count = 0, idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) != -1) {
            count++;
            idx += needle.length();
        }
        return count;
    }
}
