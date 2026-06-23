package pro.lawcybug.scanner.detectors.authzbypass;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.RequestFingerprintGuard;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Authorization Bypass (Broken Function Level Authorization / forced
 * browsing) CONFIRMATION detector.
 *
 * Only meaningful precondition for this detector: the BASE request, sent
 * as-is, must have been REJECTED (401/403, or a redirect to a login page)
 * -- i.e. we know this resource is supposed to require authorization we
 * don't currently have. From there we try a battery of well-known
 * authorization-bypass techniques that real-world frameworks/proxies have
 * been shown to mishandle, and flag anything that flips the result to a
 * success response as a CONFIRMED bypass (not a guess) -- because we
 * directly compare against the base request's own rejected outcome.
 *
 * Techniques attempted (each is cheap, single extra request):
 *   1. HTTP method override: GET<->POST<->PUT and the classic X-HTTP-
 *      Method-Override / X-HTTP-Method / X-Method-Override headers, which
 *      some frameworks honor for routing but some authz middleware does
 *      not re-check.
 *   2. Path case manipulation (/Admin vs /admin) -- catches authz rules
 *      implemented as exact-string matches on case-sensitive filesystems/
 *      routers sitting behind case-insensitive proxies.
 *   3. Trailing slash / double slash / dot-segment normalization
 *      (/admin/, /admin//, /admin/.) -- catches authz middleware that
 *      matches the raw path before the router/proxy normalizes it.
 *   4. Header-based internal-trust bypass: X-Original-URL, X-Rewrite-URL,
 *      X-Forwarded-For: 127.0.0.1, X-Custom-IP-Authorization -- catches
 *      reverse-proxy/internal-trust patterns where an edge component
 *      strips these but a misconfigured deployment doesn't.
 *   5. Wildcard/JSON content-type confusion is intentionally NOT attempted
 *      here since it overlaps with mass-assignment territory already
 *      covered elsewhere.
 *
 * Each technique is tried independently and the FIRST one that flips a
 * 401/403/redirect into a 2xx success is reported (further techniques are
 * still tried and, if also successful, are appended as extra evidence) so
 * a single base request can surface multiple concrete bypass vectors in
 * one pass without needing N separate scans.
 */
public final class AuthzBypassDetector implements ActiveDetector {

    public static final String ID = "authz.bypass.forced_browsing";

    // This detector ignores the insertion point entirely -- it probes the
    // WHOLE request (method/path/header mutations). Without this guard,
    // a request with N parameters would re-run the entire bypass battery
    // N times against the identical underlying request.
    private final RequestFingerprintGuard guard = new RequestFingerprintGuard();

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Authorization Bypass (Method/Path Mutation, Forced Browsing)"; }
    @Override public String description() { return "Confirms broken function-level authorization by flipping a rejected request to success via known bypass techniques."; }
    @Override public String category()    { return "Access Control"; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.response() == null || base.request() == null) return issues;

        if (!looksRejected(base)) {
            return issues; // base request already succeeds -- nothing to "bypass"
        }

        if (!guard.claim(base)) {
            return issues; // already ran the full bypass battery for this exact request very recently
        }

        List<BypassAttempt> confirmedBypasses = new ArrayList<>();

        confirmedBypasses.addAll(tryMethodOverrides(ctx, base));
        confirmedBypasses.addAll(tryPathMutations(ctx, base));
        confirmedBypasses.addAll(tryTrustHeaders(ctx, base));

        if (confirmedBypasses.isEmpty()) return issues;

        StringBuilder detail = new StringBuilder();
        detail.append(IssueFactory.evidenceParagraph("Base request status (rejected as expected)",
                String.valueOf(base.response().statusCode())));
        detail.append("<p>The following independent technique(s) flipped this rejected request into a "
                + "successful response, confirming broken function-level authorization:</p><ul>");
        List<HttpRequestResponse> evidence = new ArrayList<>();
        evidence.add(base);
        for (BypassAttempt attempt : confirmedBypasses) {
            detail.append("<li><b>").append(IssueFactory.escapeHtml(attempt.technique))
                    .append("</b> -- resulting status: ").append(attempt.result.response().statusCode())
                    .append("</li>");
            evidence.add(attempt.result);
        }
        detail.append("</ul>");

        issues.add(IssueFactory.build(
                "Authorization Bypass Confirmed - " + confirmedBypasses.get(0).technique,
                detail.toString(),
                "Enforce authorization checks in a single, centralized layer that operates on the fully "
                        + "normalized request (after method/path canonicalization, with all client-supplied "
                        + "override/trust headers stripped at the edge) rather than relying on exact-string "
                        + "matches against the raw incoming method/path/headers. Re-validate authorization on "
                        + "every internal hop, not just at the edge proxy.",
                base.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                "Broken Function Level Authorization occurs when an endpoint correctly rejects a "
                        + "straightforward request but can still be reached via an alternate method, path "
                        + "form, or trusted-internal-header technique that the authorization layer fails to "
                        + "canonicalize/check consistently with the routing layer.",
                evidence.toArray(new HttpRequestResponse[0])));

        return issues;
    }

    private boolean looksRejected(HttpRequestResponse base) {
        int status = base.response().statusCode();
        if (status == 401 || status == 403) return true;
        if (status >= 300 && status < 400) {
            String location = headerValue(base.response(), "Location");
            return location != null && location.toLowerCase(Locale.ROOT).contains("login");
        }
        return false;
    }

    private String headerValue(burp.api.montoya.http.message.HttpMessage message, String name) {
        return message.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(burp.api.montoya.http.message.HttpHeader::value)
                .findFirst().orElse(null);
    }

    private boolean isSuccess(HttpRequestResponse result) {
        if (result == null || result.response() == null) return false;
        int status = result.response().statusCode();
        return status >= 200 && status < 300;
    }

    private List<BypassAttempt> tryMethodOverrides(DetectorContext ctx, HttpRequestResponse base) {
        List<BypassAttempt> found = new ArrayList<>();
        String originalMethod = base.request().method();

        String[] alternateMethods = originalMethod.equalsIgnoreCase("GET")
                ? new String[]{"POST", "PUT"}
                : new String[]{"GET"};

        for (String alt : alternateMethods) {
            try {
                HttpRequest mutated = base.request().withMethod(alt);
                HttpRequestResponse result = ctx.api().http().sendRequest(mutated);
                if (isSuccess(result)) {
                    found.add(new BypassAttempt("HTTP method changed from " + originalMethod + " to " + alt, result));
                }
            } catch (Exception ignored) { }
        }

        // Method-override headers, keeping the original method but adding the header.
        for (String headerName : List.of("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override")) {
            try {
                HttpRequest mutated = base.request().withAddedHeader(headerName, "GET");
                HttpRequestResponse result = ctx.api().http().sendRequest(mutated);
                if (isSuccess(result)) {
                    found.add(new BypassAttempt("Method-override header " + headerName + ": GET", result));
                }
            } catch (Exception ignored) { }
        }

        return found;
    }

    private List<BypassAttempt> tryPathMutations(DetectorContext ctx, HttpRequestResponse base) {
        List<BypassAttempt> found = new ArrayList<>();
        String path = base.request().path();
        if (path == null || path.isEmpty()) return found;

        List<String[]> mutations = new ArrayList<>();
        mutations.add(new String[]{"trailing slash", path.endsWith("/") ? path : path + "/"});
        mutations.add(new String[]{"double slash prefix", path.replaceFirst("^/", "//")});
        mutations.add(new String[]{"dot-segment suffix", path + "/."});
        mutations.add(new String[]{"case-flipped final segment", caseFlipLastSegment(path)});
        mutations.add(new String[]{"trailing %2e", path + "%2e"});
        mutations.add(new String[]{"semicolon path parameter injection", path + ";/"});

        for (String[] mutation : mutations) {
            String label = mutation[0];
            String newPath = mutation[1];
            if (newPath.equals(path)) continue;
            try {
                HttpRequest mutated = base.request().withPath(newPath);
                HttpRequestResponse result = ctx.api().http().sendRequest(mutated);
                if (isSuccess(result)) {
                    found.add(new BypassAttempt("Path mutation (" + label + "): " + newPath, result));
                }
            } catch (Exception ignored) { }
        }

        return found;
    }

    private List<BypassAttempt> tryTrustHeaders(DetectorContext ctx, HttpRequestResponse base) {
        List<BypassAttempt> found = new ArrayList<>();
        String path = base.request().path();

        List<String[]> headerAttempts = new ArrayList<>();
        headerAttempts.add(new String[]{"X-Original-URL", path});
        headerAttempts.add(new String[]{"X-Rewrite-URL", path});
        headerAttempts.add(new String[]{"X-Forwarded-For", "127.0.0.1"});
        headerAttempts.add(new String[]{"X-Custom-IP-Authorization", "127.0.0.1"});
        headerAttempts.add(new String[]{"X-Forwarded-Host", "localhost"});
        headerAttempts.add(new String[]{"X-Originating-IP", "127.0.0.1"});
        headerAttempts.add(new String[]{"X-Remote-IP", "127.0.0.1"});
        headerAttempts.add(new String[]{"X-Client-IP", "127.0.0.1"});

        for (String[] attempt : headerAttempts) {
            String headerName = attempt[0];
            String headerValue = attempt[1];
            try {
                // For the URL-rewrite-style headers, request the bland root
                // path while smuggling the real protected path in the
                // header -- this is the actual exploitation shape for that
                // class of bypass (some front-end proxies route based on
                // the header rather than the request line).
                HttpRequest mutated = (headerName.equals("X-Original-URL") || headerName.equals("X-Rewrite-URL"))
                        ? base.request().withPath("/").withAddedHeader(headerName, headerValue)
                        : base.request().withAddedHeader(headerName, headerValue);

                HttpRequestResponse result = ctx.api().http().sendRequest(mutated);
                if (isSuccess(result)) {
                    found.add(new BypassAttempt("Trust header " + headerName + ": " + headerValue, result));
                }
            } catch (Exception ignored) { }
        }

        return found;
    }

    private String caseFlipLastSegment(String path) {
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == path.length() - 1) return path;
        String prefix = path.substring(0, lastSlash + 1);
        String segment = path.substring(lastSlash + 1);
        StringBuilder flipped = new StringBuilder();
        for (char c : segment.toCharArray()) {
            flipped.append(Character.isUpperCase(c) ? Character.toLowerCase(c) : Character.toUpperCase(c));
        }
        return prefix + flipped;
    }

    private static final class BypassAttempt {
        final String technique;
        final HttpRequestResponse result;

        BypassAttempt(String technique, HttpRequestResponse result) {
            this.technique = technique;
            this.result = result;
        }
    }
}
