package trust_system_lib;

import java.util.Map;
import java.util.HashMap;

/**
 * URLTrust.java
 * --------------
 * An independent URL-based trust layer that runs in parallel
 * with WhatsTrust (Socialtrust).
 *
 * The final trust decision in WhatsTrustTM requires BOTH:
 *   1. WhatsTrust user trust >= 0.5
 *   2. URLTrust.isSafe() == true
 */
public class URLTrust {

    private Map<String, Integer> urlCache = new HashMap<>();

    private int totalChecked    = 0;
    private int phishingFound   = 0;
    private int legitimateFound = 0;

    public void loadCache(Map<String, Integer> cache) {
        this.urlCache = new HashMap<>(cache);
    }

    public boolean isSafe(String url) {
        if (url == null) return true;
        totalChecked++;
        int result = urlCache.getOrDefault(url, 1);
        if (result == 0) {
            phishingFound++;
            return false;
        } else {
            legitimateFound++;
            return true;
        }
    }

    public boolean isKnown(String url) {
        return urlCache.containsKey(url);
    }

    public int getCacheSize() {
        return urlCache.size();
    }

    public void printStats() {
        System.out.printf("\n[URLTrust] URL Trust Layer Stats:\n");
        System.out.printf("  URLs in cache:        %d\n", urlCache.size());
        System.out.printf("  URLs checked:         %d\n", totalChecked);
        System.out.printf("  Legitimate:           %d\n", legitimateFound);
        System.out.printf("  Phishing:             %d\n", phishingFound);
        if (totalChecked > 0)
            System.out.printf("  Phishing rate:        %.2f%%\n",
                phishingFound * 100.0 / totalChecked);
    }
}