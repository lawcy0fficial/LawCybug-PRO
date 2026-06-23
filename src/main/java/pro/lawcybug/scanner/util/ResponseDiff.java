package pro.lawcybug.scanner.util;

import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Helpers for comparing two HTTP responses to decide whether a
 * "true condition" payload and a "false condition" payload produced
 * meaningfully different application behaviour -- the core signal for
 * boolean-based blind injection detection.
 */
public final class ResponseDiff {

    private ResponseDiff() {
    }

    /** Simple word-count based similarity heuristic, robust to small dynamic content (timestamps, csrf tokens). */
    public static double similarity(HttpResponse a, HttpResponse b) {
        String bodyA = a.bodyToString();
        String bodyB = b.bodyToString();
        if (bodyA.equals(bodyB)) {
            return 1.0;
        }
        String[] wordsA = tokenize(bodyA);
        String[] wordsB = tokenize(bodyB);
        if (wordsA.length == 0 && wordsB.length == 0) {
            return 1.0;
        }

        java.util.Map<String, Integer> freqA = frequency(wordsA);
        java.util.Map<String, Integer> freqB = frequency(wordsB);

        java.util.Set<String> allWords = new java.util.HashSet<>();
        allWords.addAll(freqA.keySet());
        allWords.addAll(freqB.keySet());

        long dot = 0;
        long magA = 0;
        long magB = 0;
        for (String w : allWords) {
            int ca = freqA.getOrDefault(w, 0);
            int cb = freqB.getOrDefault(w, 0);
            dot += (long) ca * cb;
            magA += (long) ca * ca;
            magB += (long) cb * cb;
        }
        if (magA == 0 || magB == 0) {
            return 0.0;
        }
        return dot / (Math.sqrt(magA) * Math.sqrt(magB));
    }

    public static boolean statusCodeDiffers(HttpResponse a, HttpResponse b) {
        return a.statusCode() != b.statusCode();
    }

    public static int bodyLengthDelta(HttpResponse a, HttpResponse b) {
        return Math.abs(a.body().length() - b.body().length());
    }

    private static String[] tokenize(String body) {
        if (body == null || body.isEmpty()) {
            return new String[0];
        }
        return body.toLowerCase().split("[^a-z0-9]+");
    }

    private static java.util.Map<String, Integer> frequency(String[] words) {
        java.util.Map<String, Integer> freq = new java.util.HashMap<>();
        for (String w : words) {
            if (w.isEmpty()) continue;
            freq.merge(w, 1, Integer::sum);
        }
        return freq;
    }
}
