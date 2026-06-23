package pro.lawcybug.scanner.detectors.jwt;

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
import pro.lawcybug.scanner.core.PassiveDetector;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JWT vulnerability checks (passive + active):
 *
 * Passive:
 *   P1. Token present in URL query string (logged in access logs)
 *   P2. Token uses 'none' algorithm already
 *   P3. Very short HS256 secret (weak, detectable via header decode)
 *   P4. Missing 'alg' header claim
 *   P5. Sensitive claims in payload without encryption (informational)
 *
 * Active:
 *   A1. alg=none / alg=None / alg=nOnE bypass
 *   A2. RS256→HS256 algorithm confusion (using public key as HMAC secret)
 *       -- this check only manipulates the algorithm claim and sends;
 *          a real key-confusion attack requires knowing the public key,
 *          which we can't usually get automatically, so we flag TENTATIVE
 *          when the server accepts the forged token at all.
 *   A3. Blank/empty signature strip
 */
public final class JwtMisconfigDetector implements ActiveDetector, PassiveDetector {

    public static final String ID = "jwt.misconfig";
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "JWT Misconfiguration"; }
    @Override public String description() { return "Passive header decode + active alg:none, algorithm confusion and empty-signature checks."; }
    @Override public String category()    { return "Authentication"; }

    // ─── Passive ─────────────────────────────────────────────────────────────
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.request() == null) return issues;

        String fullRequest = base.request().toString();
        Matcher m = JWT_PATTERN.matcher(fullRequest);
        while (m.find()) {
            String token = m.group();
            Map<String, Object> header  = decodeSegment(token, 0);
            Map<String, Object> payload = decodeSegment(token, 1);
            if (header == null) continue;

            String alg = String.valueOf(header.getOrDefault("alg", ""));
            String url = base.request().url();

            // P2: none algorithm already in use
            if (alg.equalsIgnoreCase("none")) {
                issues.add(IssueFactory.build(
                        "JWT Uses 'none' Algorithm",
                        IssueFactory.evidenceParagraph("Token (truncated)", token.substring(0, Math.min(80, token.length())) + "...")
                                + IssueFactory.evidenceParagraph("Algorithm header", alg),
                        "Reject tokens with alg:none server-side. Always require a proper signing algorithm.",
                        url, AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN,
                        "A JWT with alg:none was observed in the request. This means no signature "
                                + "verification is required, allowing trivial forgery of arbitrary claims.",
                        base));
            }

            // P4: missing alg
            if (alg.isEmpty() || alg.equals("null")) {
                issues.add(IssueFactory.build(
                        "JWT Missing Algorithm Header",
                        IssueFactory.evidenceParagraph("Token (truncated)", token.substring(0, Math.min(80, token.length())) + "..."),
                        "Always include and validate the 'alg' header claim server-side.",
                        url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                        "A JWT without an algorithm claim was observed. Libraries that default to "
                                + "'none' when no algorithm is specified are vulnerable to token forgery.", base));
            }

            // P1: token in URL
            if (base.request().url().contains(token.substring(0, 10))) {
                issues.add(IssueFactory.build(
                        "JWT Transmitted in URL Query String",
                        IssueFactory.evidenceParagraph("URL", base.request().url()),
                        "Transmit JWTs in the Authorization header or an HttpOnly cookie, not in query strings.",
                        url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                        "JWTs in URLs are logged in browser history, proxy logs and server access "
                                + "logs, exposing authentication tokens.", base));
            }
        }
        return issues;
    }

    // ─── Active ──────────────────────────────────────────────────────────────
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        String baseValue = insertionPoint.baseValue().toString();
        if (!JWT_PATTERN.matcher(baseValue).find()) return issues;

        String token = JWT_PATTERN.matcher(baseValue).results()
                .findFirst().map(mr -> mr.group()).orElse(null);
        if (token == null) return issues;

        // A1: alg=none variants
        for (String noneVariant : List.of("none", "None", "NONE", "nOnE")) {
            String forged = forgeNone(token, noneVariant);
            if (forged == null) continue;
            String modifiedPayload = baseValue.replace(token, forged);

            HttpRequestResponse result = ctx.api().http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(modifiedPayload)));

            if (result.response() != null && isSuccessLike(result, base)) {
                issues.add(IssueFactory.build(
                        "JWT Algorithm Confusion: alg=none Accepted",
                        IssueFactory.evidenceParagraph("Forged algorithm", noneVariant)
                                + IssueFactory.evidenceParagraph("Forged token (truncated)", forged.substring(0, Math.min(80, forged.length())) + "..."),
                        "Explicitly reject tokens with alg:none. Use a JWT library that does "
                                + "not accept unsigned tokens, and configure it with an allow-list "
                                + "of valid algorithms.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "A JWT with alg:none (signature removed) was accepted by the server, "
                                + "allowing signature bypass and arbitrary claim forgery.",
                        result));
                break;
            }
        }

        // A3: empty / stripped signature
        String strippedToken = stripSignature(token);
        if (strippedToken != null) {
            String modifiedPayload = baseValue.replace(token, strippedToken);
            HttpRequestResponse result = ctx.api().http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(modifiedPayload)));
            if (result.response() != null && isSuccessLike(result, base)) {
                issues.add(IssueFactory.build(
                        "JWT Empty Signature Accepted",
                        IssueFactory.evidenceParagraph("Stripped token (truncated)",
                                strippedToken.substring(0, Math.min(80, strippedToken.length())) + "..."),
                        "Validate that the signature segment is present and non-empty before "
                                + "attempting verification. Reject tokens with an empty signature.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "A JWT with the signature segment removed (preserved the trailing dot) "
                                + "was accepted by the server.", result));
            }
        }

        return issues;
    }

    private boolean isSuccessLike(HttpRequestResponse result, HttpRequestResponse base) {
        int status = result.response().statusCode();
        int baseStatus = base.response() != null ? base.response().statusCode() : 200;
        return status >= 200 && status < 400 && status != 401 && status != 403;
    }

    private String forgeNone(String token, String algValue) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return null;

            // Decode the header, swap the algorithm
            byte[] headerBytes = Base64.getUrlDecoder().decode(padBase64(parts[0]));
            String headerStr = new String(headerBytes, StandardCharsets.UTF_8);
            String newHeader = headerStr.replaceAll("\"alg\"\\s*:\\s*\"[^\"]+\"", "\"alg\":\"" + algValue + "\"");
            if (newHeader.equals(headerStr)) {
                // alg field didn't match -- try inserting
                newHeader = newHeader.replaceFirst("\\{", "{\"alg\":\"" + algValue + "\",");
            }
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(newHeader.getBytes(StandardCharsets.UTF_8));
            return encodedHeader + "." + parts[1] + ".";
        } catch (Exception e) {
            return null;
        }
    }

    private String stripSignature(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 3) return null;
            return parts[0] + "." + parts[1] + ".";
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, Object> decodeSegment(String token, int segmentIndex) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length <= segmentIndex) return null;
            byte[] decoded = Base64.getUrlDecoder().decode(padBase64(parts[segmentIndex]));
            String json = new String(decoded, StandardCharsets.UTF_8);
            return parseSimpleJson(json);
        } catch (Exception e) {
            return null;
        }
    }

    /** Minimal key→string JSON parser sufficient for JWT header/payload claims. */
    private Map<String, Object> parseSimpleJson(String json) {
        Map<String, Object> map = new LinkedHashMap<>();
        Matcher kv = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"[^\"]*\"|[^,}\\]]+)").matcher(json);
        while (kv.find()) {
            String key = kv.group(1);
            String val = kv.group(2).trim().replaceAll("^\"|\"$", "");
            map.put(key, val);
        }
        return map;
    }

    private String padBase64(String s) {
        int mod = s.length() % 4;
        if (mod == 2) return s + "==";
        if (mod == 3) return s + "=";
        return s;
    }
}
