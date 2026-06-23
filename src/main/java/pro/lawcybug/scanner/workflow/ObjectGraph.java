package pro.lawcybug.scanner.workflow;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passively-built map of "what objects exist and who touched them", learned
 * from ordinary traffic Burp already sees (proxy history, repeater, spider)
 * -- no extra requests are sent to build this. This is the foundation for
 * automatic BOLA/IDOR object discovery: instead of only testing IDs already
 * present in the request under test, the engine knows about every ID seen
 * anywhere else in the same host's traffic and can cross-test them.
 *
 * Resource type is inferred from the URL path segment preceding a numeric or
 * UUID-shaped identifier, e.g.:
 *   /api/users/42/profile        -> type="users",  id="42"
 *   /api/orders/8f14e-...-c9      -> type="orders", id="8f14e-...-c9"
 *   /invoices/2024/INV-9981       -> type="invoices", id="INV-9981"
 */
public final class ObjectGraph {

    /** One observed reference to a resource instance. */
    public static final class ObjectRef {
        public final String resourceType;
        public final String id;
        public final String host;
        public final Set<String> seenViaUrls = new LinkedHashSet<>();
        public final Set<String> observedWithIdentityHints = new LinkedHashSet<>();

        ObjectRef(String resourceType, String id, String host) {
            this.resourceType = resourceType;
            this.id = id;
            this.host = host;
        }

        @Override
        public String toString() {
            return resourceType + "/" + id + " @ " + host;
        }
    }

    // host -> resourceType -> id -> ref
    private final Map<String, Map<String, Map<String, ObjectRef>>> graph = new ConcurrentHashMap<>();

    private static final Pattern NUMERIC_ID_SEGMENT =
            Pattern.compile("/([a-zA-Z_][a-zA-Z0-9_-]{2,30})/(\\d{1,19})(?=/|\\?|$)");
    private static final Pattern UUID_ID_SEGMENT =
            Pattern.compile("/([a-zA-Z_][a-zA-Z0-9_-]{2,30})/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
                    + "[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|\\?|$)");
    private static final Pattern ALNUM_CODE_SEGMENT =
            Pattern.compile("/([a-zA-Z_][a-zA-Z0-9_-]{2,30})/([A-Z]{2,6}-\\d{2,12})(?=/|\\?|$)");

    // Matches "id"/"uuid"/"<thing>Id" style key-value pairs inside JSON response
    // bodies, e.g. {"id":42,...} inside a /api/orders list response -- this is
    // usually where an object ID is FIRST observed, well before it ever shows
    // up in a URL path. GraphQL "id" fields under any node also match this.
    private static final Pattern JSON_ID_FIELD =
            Pattern.compile("\"([a-zA-Z_]*[iI]d|uuid)\"\\s*:\\s*\"?([A-Za-z0-9_-]{1,64})\"?");
    private static final Pattern JSON_TYPE_HINT =
            Pattern.compile("\"(__typename|type|kind|resource[_-]?type)\"\\s*:\\s*\"([A-Za-z_][A-Za-z0-9_]*)\"");

    /** Ingest one request's URL path; cheap enough to call on every request observed. */
    public void observe(String host, String urlPath) {
        if (host == null || urlPath == null) return;
        ingest(host, urlPath, NUMERIC_ID_SEGMENT);
        ingest(host, urlPath, UUID_ID_SEGMENT);
        ingest(host, urlPath, ALNUM_CODE_SEGMENT);
    }

    /**
     * Ingest a JSON response body in addition to the URL path. This is the
     * primary source of NEW object IDs in practice: a list endpoint like
     * GET /api/orders typically returns [{"id":101,...}, {"id":102,...}]
     * long before any of those IDs ever appear in a URL -- without this,
     * the object graph only learns IDs the scanner happens to later visit
     * directly, missing most of what's actually discoverable from traffic
     * Burp has already seen.
     *
     * Resource type is inferred, in priority order:
     *   1. an explicit type hint in the same JSON object (__typename/type/kind)
     *   2. the field-name prefix itself (e.g. "orderId" -> "order")
     *   3. the resource type implied by the URL path this body came from
     *   4. "unknown" as a last resort, kept separate so it doesn't pollute
     *      a real resource type's sibling-ID pool
     */
    public void observe(String host, String urlPath, String responseBody) {
        observe(host, urlPath);
        if (host == null || responseBody == null || responseBody.isBlank()) return;

        String urlImpliedType = impliedTypeFromPath(urlPath);
        String nearestTypeHint = null;

        // Single linear scan: track the most recent __typename/type/kind seen
        // so plain "id" fields appearing shortly after can borrow it. This is
        // a heuristic, not a real JSON-tree walk, but is cheap and good enough
        // for the common "each object has its type field near its id field" shape.
        java.util.regex.Matcher idMatcher = JSON_ID_FIELD.matcher(responseBody);
        java.util.regex.Matcher typeMatcher = JSON_TYPE_HINT.matcher(responseBody);
        java.util.List<int[]> typeMatchPositions = new ArrayList<>();
        java.util.List<String> typeMatchValues = new ArrayList<>();
        while (typeMatcher.find()) {
            typeMatchPositions.add(new int[]{typeMatcher.start()});
            typeMatchValues.add(typeMatcher.group(2));
        }

        while (idMatcher.find()) {
            String fieldName = idMatcher.group(1);
            String idValue = idMatcher.group(2);
            if (idValue.isBlank()) continue;

            String type = fieldPrefixType(fieldName);
            if (type == null) {
                type = nearestTypeHintBefore(typeMatchPositions, typeMatchValues, idMatcher.start());
            }
            if (type == null) {
                type = urlImpliedType;
            }
            if (type == null) {
                type = "unknown";
            }

            String normalized = normalizeType(type);
            ObjectRef ref = graph
                    .computeIfAbsent(host, h -> new ConcurrentHashMap<>())
                    .computeIfAbsent(normalized, t -> new ConcurrentHashMap<>())
                    .computeIfAbsent(idValue, i -> new ObjectRef(normalized, i, host));
            ref.seenViaUrls.add(urlPath == null ? "(response body)" : urlPath);
        }
    }

    private String impliedTypeFromPath(String urlPath) {
        if (urlPath == null) return null;
        // Last path segment that isn't itself numeric/UUID-shaped, e.g.
        // /api/v2/orders -> "orders", /api/orders/55 -> "orders".
        String[] segments = urlPath.split("/");
        for (int i = segments.length - 1; i >= 0; i--) {
            String seg = segments[i];
            if (seg.isBlank()) continue;
            if (seg.matches("\\d+") || seg.matches("[0-9a-fA-F-]{8,}")) continue;
            if (seg.contains("?")) seg = seg.substring(0, seg.indexOf('?'));
            return seg;
        }
        return null;
    }

    private String fieldPrefixType(String fieldName) {
        // "orderId" -> "order", "user_id" -> "user", plain "id"/"uuid" -> null (no prefix to use)
        String lower = fieldName.toLowerCase().replace("_id", "").replace("id", "");
        lower = lower.replace("_", "");
        if (lower.isBlank() || fieldName.equalsIgnoreCase("id") || fieldName.equalsIgnoreCase("uuid")) {
            return null;
        }
        return lower;
    }

    private String nearestTypeHintBefore(java.util.List<int[]> positions, java.util.List<String> values, int idPos) {
        String best = null;
        int bestDistance = Integer.MAX_VALUE;
        for (int i = 0; i < positions.size(); i++) {
            int pos = positions.get(i)[0];
            int distance = Math.abs(idPos - pos);
            // Only consider type hints reasonably close to the id field (same
            // object, not a type hint from a sibling object earlier in the array).
            if (distance < 200 && distance < bestDistance) {
                bestDistance = distance;
                best = values.get(i);
            }
        }
        return best;
    }

    private void ingest(String host, String urlPath, Pattern pattern) {
        Matcher m = pattern.matcher(urlPath);
        while (m.find()) {
            String type = normalizeType(m.group(1));
            String id = m.group(2);
            ObjectRef ref = graph
                    .computeIfAbsent(host, h -> new ConcurrentHashMap<>())
                    .computeIfAbsent(type, t -> new ConcurrentHashMap<>())
                    .computeIfAbsent(id, i -> new ObjectRef(type, i, host));
            ref.seenViaUrls.add(urlPath);
        }
    }

    private String normalizeType(String segment) {
        // crude singularization so "/users/1" and "/user/2" land in one bucket
        String t = segment.toLowerCase();
        if (t.endsWith("ies")) return t.substring(0, t.length() - 3) + "y";
        if (t.endsWith("s") && !t.endsWith("ss")) return t.substring(0, t.length() - 1);
        return t;
    }

    /** All distinct IDs observed for a given resource type on a given host, excluding one ID. */
    public List<String> siblingIds(String host, String resourceType, String excludeId) {
        Map<String, ObjectRef> byId = graph.getOrDefault(host, Map.of())
                .getOrDefault(normalizeType(resourceType), Map.of());
        List<String> out = new ArrayList<>();
        for (String id : byId.keySet()) {
            if (!id.equals(excludeId)) out.add(id);
        }
        return out;
    }

    /** Best-effort guess of resource type + id for a given URL path, or null. */
    public ObjectRef extractRef(String host, String urlPath) {
        for (Pattern p : List.of(NUMERIC_ID_SEGMENT, UUID_ID_SEGMENT, ALNUM_CODE_SEGMENT)) {
            Matcher m = p.matcher(urlPath);
            if (m.find()) {
                String type = normalizeType(m.group(1));
                String id = m.group(2);
                return graph.getOrDefault(host, Map.of())
                        .getOrDefault(type, Map.of())
                        .getOrDefault(id, new ObjectRef(type, id, host));
            }
        }
        return null;
    }

    /** Generates plausible neighbouring IDs for sequential-ID enumeration (numeric only). */
    public List<String> guessNeighbourIds(String id, int spread) {
        List<String> out = new ArrayList<>();
        try {
            long n = Long.parseLong(id);
            for (int delta = -spread; delta <= spread; delta++) {
                if (delta == 0) continue;
                long candidate = n + delta;
                if (candidate >= 0) out.add(String.valueOf(candidate));
            }
        } catch (NumberFormatException ignored) {
            // non-numeric ID (UUID/code) -- no safe sequential guess, rely on siblingIds() instead
        }
        return out;
    }

    public int totalTrackedObjects() {
        return graph.values().stream()
                .flatMap(m -> m.values().stream())
                .mapToInt(Map::size)
                .sum();
    }

    public void clear() {
        graph.clear();
    }
}
