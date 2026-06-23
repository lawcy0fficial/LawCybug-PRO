package pro.lawcybug.scanner.workflow;

import java.util.*;


/**
 * Compares two HTTP responses at a structural level rather than a naive
 * byte/length diff. The key insight for BOLA/IDOR: two responses that
 * differ in every *value* but share the same JSON key-set and types are
 * far more interesting than two responses that merely differ in length --
 * that pattern ("same shape, different owner's data") is exactly what a
 * successful authorization bypass looks like.
 *
 * Falls back gracefully to non-JSON heuristics (status code, length ratio,
 * shared-token ratio) for HTML/plain-text/XML bodies.
 */
public final class ResponseSimilarityEngine {

    public static final class Verdict {
        public final boolean sameStatusCode;
        public final double lengthRatio;          // shorter/longer, 0..1
        public final boolean sameJsonShape;       // same key set + types, recursively
        public final double keyOverlapRatio;      // |intersection| / |union| of all keys
        public final boolean looksLikeBolaSuccess; // same shape, different identity-ish values
        public final List<String> differingKeys = new ArrayList<>();

        Verdict(boolean sameStatusCode, double lengthRatio, boolean sameJsonShape,
                double keyOverlapRatio, boolean looksLikeBolaSuccess) {
            this.sameStatusCode = sameStatusCode;
            this.lengthRatio = lengthRatio;
            this.sameJsonShape = sameJsonShape;
            this.keyOverlapRatio = keyOverlapRatio;
            this.looksLikeBolaSuccess = looksLikeBolaSuccess;
        }
    }

    @SuppressWarnings("unchecked")
    public Verdict compare(int statusA, String bodyA, int statusB, String bodyB) {
        boolean sameStatus = statusA == statusB;
        double lenRatio = lengthRatio(bodyA, bodyB);

        Object jsonA = tryParse(bodyA);
        Object jsonB = tryParse(bodyB);

        if (jsonA instanceof Map && jsonB instanceof Map) {
            return compareJsonObjects((Map<String, Object>) jsonA, (Map<String, Object>) jsonB,
                    sameStatus, lenRatio);
        }
        if (jsonA instanceof List && jsonB instanceof List) {
            // Arrays: compare shape of first element as a representative sample.
            List<?> la = (List<?>) jsonA;
            List<?> lb = (List<?>) jsonB;
            if (!la.isEmpty() && !lb.isEmpty() && la.get(0) instanceof Map && lb.get(0) instanceof Map) {
                return compareJsonObjects((Map<String, Object>) la.get(0), (Map<String, Object>) lb.get(0),
                        sameStatus, lenRatio);
            }
        }

        // Non-JSON fallback: same status + similar length is the best signal we get.
        boolean likelyBola = sameStatus && lenRatio > 0.85 && !bodyA.equals(bodyB);
        Verdict v = new Verdict(sameStatus, lenRatio, false, lenRatio, likelyBola);
        return v;
    }

    @SuppressWarnings("unchecked")
    private Verdict compareJsonObjects(Map<String, Object> a, Map<String, Object> b,
                                        boolean sameStatus, double lenRatio) {
        Set<String> keysA = flattenKeys(a, "");
        Set<String> keysB = flattenKeys(b, "");

        Set<String> union = new LinkedHashSet<>(keysA);
        union.addAll(keysB);
        Set<String> intersection = new LinkedHashSet<>(keysA);
        intersection.retainAll(keysB);

        double overlap = union.isEmpty() ? 1.0 : (double) intersection.size() / union.size();
        boolean sameShape = overlap >= 0.9 && typesMatch(a, b, intersection);

        Verdict v = new Verdict(sameStatus, lenRatio, sameShape, overlap,
                sameStatus && sameShape && !a.equals(b));

        for (String key : intersection) {
            Object va = dig(a, key);
            Object vb = dig(b, key);
            if (!Objects.equals(va, vb)) {
                v.differingKeys.add(key);
            }
        }
        return v;
    }

    private boolean typesMatch(Map<String, Object> a, Map<String, Object> b, Set<String> keys) {
        for (String key : keys) {
            Object va = dig(a, key);
            Object vb = dig(b, key);
            if (va == null || vb == null) continue;
            if (!va.getClass().equals(vb.getClass())) {
                // Allow Long/Integer/Double cross-matches -- MiniJson may parse numerics inconsistently.
                boolean bothNumeric = va instanceof Number && vb instanceof Number;
                if (!bothNumeric) return false;
            }
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    private Set<String> flattenKeys(Map<String, Object> map, String prefix) {
        Set<String> keys = new LinkedHashSet<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String path = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            keys.add(path);
            if (entry.getValue() instanceof Map) {
                keys.addAll(flattenKeys((Map<String, Object>) entry.getValue(), path));
            }
        }
        return keys;
    }

    @SuppressWarnings("unchecked")
    private Object dig(Map<String, Object> map, String dottedPath) {
        String[] parts = dottedPath.split("\\.");
        Object current = map;
        for (String part : parts) {
            if (!(current instanceof Map)) return null;
            current = ((Map<String, Object>) current).get(part);
        }
        return current;
    }

    private double lengthRatio(String a, String b) {
        int la = a == null ? 0 : a.length();
        int lb = b == null ? 0 : b.length();
        if (la == 0 && lb == 0) return 1.0;
        int shorter = Math.min(la, lb);
        int longer = Math.max(la, lb);
        return longer == 0 ? 1.0 : (double) shorter / longer;
    }

    private Object tryParse(String body) {
        if (body == null) return null;
        String trimmed = body.trim();
        if (trimmed.isEmpty() || !(trimmed.startsWith("{") || trimmed.startsWith("["))) {
            return null;
        }
        try {
            return JsonLite.parse(trimmed);
        } catch (Exception e) {
            return null;
        }
    }
}
