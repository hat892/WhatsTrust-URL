/**
 * WhatsTrustDecision.java
 * ------------------------
 * This class combines the WhatsTrust user trust value
 * with the URL ML classifier to make a final trust decision.
 *
 * Add this logic inside TraceSimulator.java where messages are processed.
 */
public class WhatsTrustDecision {

    // Trust threshold (from WhatsTrust paper: r = 0.5)
    private static final double TRUST_THRESHOLD = 0.5;

    /**
     * Makes a final trust decision combining user trust + URL check.
     *
     * @param message       The message content
     * @param userTrustValue The WhatsTrust computed trust value (0.0 to 1.0)
     * @return true if message is trusted, false if suspicious
     */
    public static boolean isTrusted(String message, double userTrustValue) {

        // STEP 1: Check user trust value
        boolean userTrusted = userTrustValue >= TRUST_THRESHOLD;

        // STEP 2: Check if message contains a URL
        String url = URLClassifier.extractURL(message);

        if (url == null) {
            // No URL in message — decision based on user trust only
            System.out.println("[WhatsTrust] No URL detected. Decision based on user trust only.");
            System.out.println("[WhatsTrust] User trust value: " + userTrustValue +
                               " -> " + (userTrusted ? "TRUSTED" : "NOT TRUSTED"));
            return userTrusted;

        } else {
            // URL found — run ML classifier
            System.out.println("[WhatsTrust] URL detected: " + url);
            int urlResult = URLClassifier.classify(url);

            boolean urlSafe = (urlResult == 1);
            System.out.println("[WhatsTrust] URL classification: " +
                               (urlSafe ? "LEGITIMATE" : "PHISHING"));
            System.out.println("[WhatsTrust] User trust value: " + userTrustValue);

            // STEP 3: Combined decision
            // Message is trusted ONLY if BOTH user is trusted AND URL is safe
            boolean finalDecision = userTrusted && urlSafe;

            System.out.println("[WhatsTrust] Final decision: " +
                               (finalDecision ? "TRUSTED" : "NOT TRUSTED"));
            return finalDecision;
        }
    }

    // Quick test
    public static void main(String[] args) {
        System.out.println("=== WhatsTrust Decision Test ===\n");

        // Test 1: Trusted user, no URL
        System.out.println("Test 1: Trusted user, no URL");
        isTrusted("Hey, are you coming tonight?", 0.85);

        System.out.println();

        // Test 2: Trusted user, safe URL
        System.out.println("Test 2: Trusted user, safe URL");
        isTrusted("Check this out: https://www.google.com", 0.85);

        System.out.println();

        // Test 3: Trusted user, suspicious URL
        System.out.println("Test 3: Trusted user, phishing URL");
        isTrusted("Win a prize! https://g00gle-free-gift.ru/claim?id=123", 0.85);

        System.out.println();

        // Test 4: Untrusted user, even with safe URL
        System.out.println("Test 4: Untrusted user, safe URL");
        isTrusted("Check this: https://www.google.com", 0.2);
    }
}