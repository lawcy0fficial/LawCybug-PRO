package pro.lawcybug.scanner.workflow;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A named, swappable credential set (e.g. "Victim", "Attacker", "Anonymous").
 * Holds whatever headers/cookies are needed to authenticate as that identity,
 * and knows how to stamp those credentials onto an arbitrary outgoing request
 * so the same logical request can be cheaply replayed as a different user.
 *
 * Deliberately header/cookie based rather than tied to any one auth scheme
 * (cookie session, Bearer JWT, custom API key header, etc.) so it works
 * uniformly across REST, GraphQL and legacy session-cookie apps.
 */
public final class SessionIdentity {

    public enum Role {
        VICTIM, ATTACKER, ANONYMOUS, ADMIN, CUSTOM
    }

    private final String name;
    private final Role role;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private String cookieHeaderValue;

    public SessionIdentity(String name, Role role) {
        this.name = name;
        this.role = role;
    }

    public static SessionIdentity anonymous() {
        return new SessionIdentity("Anonymous", Role.ANONYMOUS);
    }

    public SessionIdentity withHeader(String name, String value) {
        this.headers.put(name, value);
        return this;
    }

    public SessionIdentity withCookie(String rawCookieHeaderValue) {
        this.cookieHeaderValue = rawCookieHeaderValue;
        return this;
    }

    public SessionIdentity withBearerToken(String token) {
        return withHeader("Authorization", "Bearer " + token);
    }

    public String name() {
        return name;
    }

    public Role role() {
        return role;
    }

    public Map<String, String> headers() {
        return headers;
    }

    public String cookieHeaderValue() {
        return cookieHeaderValue;
    }

    /**
     * Returns a copy of {@code request} re-stamped with this identity's
     * credentials: every configured header is set/overwritten, and the
     * Cookie header (if any) is replaced wholesale rather than merged,
     * since mixing two users' session cookies is almost never desired.
     */
    public HttpRequest stamp(HttpRequest request) {
        HttpRequest result = request;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            result = result.withUpdatedHeader(entry.getKey(), entry.getValue());
        }
        if (cookieHeaderValue != null && !cookieHeaderValue.isBlank()) {
            result = result.withUpdatedHeader("Cookie", cookieHeaderValue);
        }
        return result;
    }

    @Override
    public String toString() {
        return "SessionIdentity{" + name + ", role=" + role + "}";
    }
}
