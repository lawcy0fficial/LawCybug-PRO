package pro.lawcybug.scanner.util;

import java.security.SecureRandom;

/** Generates short, low-collision random tokens used as reflection canaries. */
public final class CanaryUtils {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

    private CanaryUtils() {
    }

    public static String randomToken(int length) {
        StringBuilder sb = new StringBuilder("lcb");
        for (int i = 0; i < length; i++) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    public static String randomToken() {
        return randomToken(8);
    }
}
