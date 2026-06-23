package pro.lawcybug.scanner.detectors.oauth;

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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OAuth 2.0 / OIDC authorization-flow security checks. Targets the
 * authorize/callback/token endpoints specifically rather than generic
 * traffic, since these checks are meaningless anywhere else.
 *
 * Covers (passive, traffic-driven, no extra requests unless noted):
 *   1. Missing/predictable `state` parameter (CSRF on the OAuth flow)
 *   2. Missing PKCE (`code_challenge`) on a public/native-looking client
 *   3. Authorization code or access token leaking into the Referer header
 *      on the callback page's first outbound request (e.g. to an analytics
 *      or CDN domain) -- a real, frequently-reported leak vector
 *   4. `redirect_uri` accepted with an open/loose match (active probe:
 *      replays the authorize request with a subtly modified redirect_uri
 *      and checks whether the server still issues a code/token to it)
 *   5. Implicit flow usage (`response_type=token`) -- deprecated by the
 *      OAuth 2.0 Security BCP due to token exposure in the URL fragment/
 *      browser history/Referer
 */
public final class OAuthSecurityDetector implements PassiveDetector, ActiveDetector {

    private static final String ID = "oauth-security";

    private static final Pattern AUTHORIZE_PATH =
            Pattern.compile("/(oauth2?/)?authorize", Pattern.CASE_INSENSITIVE);
    private static final Pattern TOKEN_PATH =
            Pattern.compile("/(oauth2?/)?token", Pattern.CASE_INSENSITIVE);

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "OAuth / OIDC Security Suite";
    }

    @Override
    public String description() {
        return "Checks OAuth/OIDC authorization flows for missing state/PKCE, implicit-flow usage, "
                + "token/code leakage via Referer, and loose redirect_uri validation.";
    }

    @Override
    public String category() {
        return "Authentication / OAuth";
    }

    // ---------------------------------------------------------------
    // Passive checks against traffic already observed.
    // ---------------------------------------------------------------
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse rr) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpRequest req = rr.request();
        if (req == null) return issues;
        String path = req.path();

        if (AUTHORIZE_PATH.matcher(path).find()) {
            issues.addAll(checkAuthorizeRequest(req));
        }

        // Referer leak check: any outbound request whose Referer header contains
        // an oauth "code=" or "access_token=" param means a prior redirect leaked it.
        String referer = headerValue(req, "Referer");
        if (referer != null) {
            Matcher leak = Pattern.compile("[?&#](code|access_token|id_token)=([^&\\s]+)").matcher(referer);
            if (leak.find()) {
                String host = req.httpService().host();
                issues.add(IssueFactory.build(
                        "OAuth Token/Code Leakage via Referer",
                        "<p>An outbound request to <code>" + IssueFactory.escapeHtml(host)
                                + "</code> carried a <code>Referer</code> header containing an OAuth "
                                + "<code>" + leak.group(1) + "</code> value. If the OAuth callback page loads "
                                + "any third-party resource (analytics, ads, CDN, web fonts) before stripping "
                                + "the code/token from the URL, that third party's server receives it via "
                                + "the Referer header.</p>"
                                + IssueFactory.evidenceParagraph("Leaking to host", host)
                                + IssueFactory.evidenceParagraph("Leaked parameter", leak.group(1)),
                        "<p>Strip the authorization code/token from the URL (e.g. via "
                                + "<code>history.replaceState</code>) immediately on the callback page, before "
                                + "any third-party resource is loaded, and prefer the `state`-only redirect "
                                + "pattern where the code is exchanged server-side.</p>",
                        req.url(),
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.FIRM,
                        null,
                        rr
                ));
            }
        }

        return issues;
    }

    private List<AuditIssue> checkAuthorizeRequest(HttpRequest req) {
        List<AuditIssue> issues = new ArrayList<>();
        String url = req.url();

        String state = queryParam(url, "state");
        String codeChallenge = queryParam(url, "code_challenge");
        String responseType = queryParam(url, "response_type");

        if (state == null || state.isBlank()) {
            issues.add(IssueFactory.build(
                    "OAuth Authorization Request Missing `state` Parameter",
                    "<p>This authorization request has no <code>state</code> parameter (or it's empty). "
                            + "Without it, the OAuth flow is vulnerable to CSRF: an attacker can initiate "
                            + "their own authorization flow, capture the resulting code, and trick a victim "
                            + "into completing the callback with the attacker's code -- binding the victim's "
                            + "session to the attacker's account (login CSRF / account-linking attack).</p>"
                            + IssueFactory.evidenceParagraph("Authorize URL", url),
                    "<p>Generate a cryptographically random, unguessable <code>state</code> value per "
                            + "authorization request, store it server-side (or in a signed cookie) tied to "
                            + "the user's session, and verify it matches exactly on the callback.</p>",
                    url,
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    null
            ));
        } else if (looksPredictable(state)) {
            issues.add(IssueFactory.build(
                    "OAuth `state` Parameter Looks Predictable",
                    "<p>The <code>state</code> value <code>" + IssueFactory.escapeHtml(state)
                            + "</code> looks sequential, short, or otherwise low-entropy rather than a "
                            + "cryptographically random token, weakening its CSRF protection.</p>"
                            + IssueFactory.evidenceParagraph("Authorize URL", url),
                    "<p>Use a cryptographically random value of at least 128 bits of entropy for `state`.</p>",
                    url,
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.TENTATIVE,
                    null
            ));
        }

        if ("token".equalsIgnoreCase(responseType) || "id_token".equalsIgnoreCase(responseType)) {
            issues.add(IssueFactory.build(
                    "OAuth Implicit Flow In Use",
                    "<p>This authorization request uses <code>response_type=" + IssueFactory.escapeHtml(responseType)
                            + "</code> (the Implicit flow), which returns the access/ID token directly in the "
                            + "URL fragment. The OAuth 2.0 Security Best Current Practice (BCP) deprecates this "
                            + "flow because the token ends up in browser history, Referer headers, and any "
                            + "JS running on the page, with no way to revoke an exposed token short of its "
                            + "natural expiry.</p>"
                            + IssueFactory.evidenceParagraph("Authorize URL", url),
                    "<p>Migrate to Authorization Code flow with PKCE, even for public/SPA clients.</p>",
                    url,
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.CERTAIN,
                    null
            ));
        }

        if (codeChallenge == null || codeChallenge.isBlank()) {
            // Only a LEAD at MEDIUM/TENTATIVE -- confidential (server-side) clients
            // legitimately may skip PKCE since they have a client_secret; we can't
            // tell client type from this single request alone.
            issues.add(IssueFactory.build(
                    "OAuth Authorization Request Missing PKCE",
                    "<p>No <code>code_challenge</code> parameter is present. If this is a public client "
                            + "(SPA, mobile app, or any client that can't keep a client_secret confidential), "
                            + "the authorization code is exchangeable by anyone who intercepts it (e.g. via a "
                            + "malicious app registering the same custom URI scheme on mobile) -- PKCE is the "
                            + "mitigation. Confidential server-side clients with a real client_secret are not "
                            + "affected; verify client type before treating this as a confirmed finding.</p>"
                            + IssueFactory.evidenceParagraph("Authorize URL", url),
                    "<p>Implement PKCE (RFC 7636) for all public clients: generate a random "
                            + "<code>code_verifier</code>, send its SHA-256 hash as <code>code_challenge</code> "
                            + "on the authorize request, and the raw verifier on the token exchange.</p>",
                    url,
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.TENTATIVE,
                    null
            ));
        }

        return issues;
    }

    // ---------------------------------------------------------------
    // Active: redirect_uri validation looseness probe.
    // ---------------------------------------------------------------
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse baseRequestResponse,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpRequest base = baseRequestResponse.request();
        if (!AUTHORIZE_PATH.matcher(base.path()).find()) {
            return issues;
        }

        String redirectUri = queryParam(base.url(), "redirect_uri");
        if (redirectUri == null || redirectUri.isBlank()) {
            return issues;
        }

        for (String variant : buildRedirectUriVariants(redirectUri)) {
            try {
                String mutatedUrl = base.url().replace(
                        "redirect_uri=" + urlEncode(redirectUri),
                        "redirect_uri=" + urlEncode(variant));
                if (mutatedUrl.equals(base.url())) continue;

                HttpRequest probe = base.withPath(pathAndQueryOf(mutatedUrl));
                HttpRequestResponse result = ctx.api().http().sendRequest(probe);
                if (result.response() == null) continue;

                int status = result.response().statusCode();
                String location = headerValue(result.response().headers(), "Location");
                boolean redirectedToVariant = location != null && location.startsWith(variant);
                boolean serverError = status >= 400;

                if (!serverError && (redirectedToVariant || status == 302 || status == 303)) {
                    issues.add(IssueFactory.build(
                            "OAuth redirect_uri Validation Bypass (Open Redirect Chain Risk)",
                            "<p>Replacing the registered <code>redirect_uri</code> value <code>"
                                    + IssueFactory.escapeHtml(redirectUri) + "</code> with the variant <code>"
                                    + IssueFactory.escapeHtml(variant)
                                    + "</code> was accepted (HTTP " + status + ") rather than rejected. Loose "
                                    + "redirect_uri matching (substring/prefix/subdomain match instead of exact "
                                    + "match) lets an attacker redirect the authorization code or token to a "
                                    + "host they control, leading directly to account takeover.</p>"
                                    + IssueFactory.evidenceParagraph("Original redirect_uri", redirectUri)
                                    + IssueFactory.evidenceParagraph("Accepted variant", variant),
                            "<p>Validate <code>redirect_uri</code> with an EXACT, case-sensitive string match "
                                    + "against a pre-registered allow-list -- no prefix, substring, subdomain, "
                                    + "or open-path matching.</p>",
                            base.url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.TENTATIVE,
                            "<p>Confirm manually: some servers return 302 to an interim consent/login page "
                                    + "regardless of redirect_uri validity, which would look like a false "
                                    + "positive here. The real test is whether the FINAL redirect (post-consent, "
                                    + "carrying the code/token) lands on the attacker-controlled variant.</p>",
                            result
                    ));
                    break; // one confirmed-looking variant is enough signal; avoid noisy duplicates
                }
            } catch (Exception ignored) {
            }
        }

        return issues;
    }

    private List<String> buildRedirectUriVariants(String original) {
        List<String> variants = new ArrayList<>();
        try {
            java.net.URI uri = java.net.URI.create(original);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            String path = uri.getRawPath() == null ? "" : uri.getRawPath();
            if (host == null) return variants;

            variants.add(scheme + "://" + host + ".attacker-lcb-test.com" + path);   // subdomain-suffix trick
            variants.add(scheme + "://attacker-lcb-test.com/" + host + path);         // path-confusion trick
            variants.add(original + ".attacker-lcb-test.com");                        // naive suffix append
            variants.add(original.endsWith("/") ? original + "../" : original + "/../"); // path traversal
        } catch (Exception ignored) {
        }
        return variants;
    }

    // ---------------------------------------------------------------
    private boolean looksPredictable(String state) {
        if (state.length() < 16) return true;
        return state.matches("\\d+") || state.matches("[0-9a-fA-F]{1,8}");
    }

    private String queryParam(String url, String name) {
        Matcher m = Pattern.compile("[?&]" + Pattern.quote(name) + "=([^&#]*)").matcher(url);
        if (!m.find()) return null;
        try {
            return URLDecoder.decode(m.group(1), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return m.group(1);
        }
    }

    private String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String pathAndQueryOf(String fullUrl) {
        int idx = fullUrl.indexOf('/', fullUrl.indexOf("://") + 3);
        return idx == -1 ? "/" : fullUrl.substring(idx);
    }

    private String headerValue(HttpRequest req, String name) {
        return req.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(h -> h.value())
                .findFirst().orElse(null);
    }

    private String headerValue(List<burp.api.montoya.http.message.HttpHeader> headers, String name) {
        return headers.stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(h -> h.value())
                .findFirst().orElse(null);
    }
}
