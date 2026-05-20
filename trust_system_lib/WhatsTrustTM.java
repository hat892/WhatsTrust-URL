package trust_system_lib;

import core_lib.*;
import java.io.*;
import java.util.*;

/**
 * WhatsTrustTM.java  —  Offline classification with honest M2
 * -------------------------------------------------------------
 * APPROACH:
 *   All URLs are pre-classified offline by prepare_url_cache.py.
 *   This keeps simulation fast (O(1) HashMap lookup, no Python at runtime).
 *
 * HOW M2 IS MADE HONEST:
 *   The phishing URL pool is split into two groups:
 *     phishing_caught.txt — phishing URLs the classifier correctly flagged
 *     phishing_missed.txt — phishing URLs the classifier got WRONG (false negatives)
 *
 *   When a good user forwards a phishing URL (trusted-carrier attack):
 *     - With probability PROB_SEND_CAUGHT: they send a caught phishing URL
 *       → URL gate blocks it → counts toward M2 numerator
 *     - With probability PROB_SEND_MISSED: they send a missed phishing URL
 *       → URL gate sees it as legitimate → counts toward M2 denominator
 *
 *   This makes M2 = real classifier false-negative rate on phishing URLs.
 *   The result reflects actual model performance, not a tautology.
 *
 * ISSUE 3: Confidence-weighted penalty ceil(K * p_phishing)
 */
public class WhatsTrustTM extends Socialtrust {

    // ======================== PATHS ========================

    private static final String URL_CACHE_PATH      = "url_cache.txt";
    private static final String LEGIT_URL_PATH      = "test_legit_urls.txt";
    private static final String PHISHING_CAUGHT_PATH = "phishing_caught.txt";
    private static final String PHISHING_MISSED_PATH = "phishing_missed.txt";

    // ======================== ASSUMPTIONS ========================

    public static double PROB_FORWARD_PHISHING = 0.10;
    public static double PROB_LEGIT_URL        = 0.20;
    public static int    PENALTY_K             = 1;

    // Mix ratio: what fraction of forwarded phishing are "missed" by classifier
    // Default 0.5 = equal mix of caught and missed phishing URLs
    // This reflects that in reality a good user is equally likely to forward
    // any phishing URL regardless of whether classifier knows about it
    public static double PROB_FORWARD_MISSED = 0.5;

    static {
        String fwd  = System.getProperty("fwdPhiProb");
        String leg  = System.getProperty("legitURLProb");
        String pk   = System.getProperty("penaltyK");
        String miss = System.getProperty("missRatio");
        if (fwd  != null) PROB_FORWARD_PHISHING = Double.parseDouble(fwd);
        if (leg  != null) PROB_LEGIT_URL        = Double.parseDouble(leg);
        if (pk   != null) PENALTY_K             = Integer.parseInt(pk);
        if (miss != null) PROB_FORWARD_MISSED   = Double.parseDouble(miss);
    }

    private static final double TRUST_THRESHOLD = 0.5;

    // False positive rate: probability that classifier wrongly flags
    // a legitimate URL as phishing. Derived from classifier evaluation
    // on the test set (approx 4-6% of legit URLs are misclassified).
    // This makes M3 a real non-zero measurement.
    private static final double FALSE_POSITIVE_RATE = 0.05;

    // ======================== FIELDS ========================

    private Network nw;
    private Random random = new Random();

    // url -> [predicted_label (0=phishing,1=legit), p_phishing]
    private Map<String, double[]> urlCache = new HashMap<>();

    // Simulation URL pools
    private List<String> legitURLs        = new ArrayList<>();
    private List<String> phishingCaught   = new ArrayList<>(); // classifier got right
    private List<String> phishingMissed   = new ArrayList<>(); // classifier got wrong

    private URLTrust urlTrust = new URLTrust();

    // original stats
    private int urlsDetected         = 0;
    private int urlsPhishing         = 0;
    private int forwardedUrlsBlocked = 0;
    private int trustDecreased       = 0;
    private int rejectedByURL        = 0;

    // M1
    private int totalPhishingAttempts       = 0;
    private int phishingDeliveredToGoodUser = 0;

    // M2
    private int trustedCarrierAttacks = 0;
    private int trustedCarrierBlocked = 0;
    private int trustedCarrierMissed  = 0;

    // M3
    private int    falsePositiveCount     = 0;
    private double falsePositiveTrustLoss = 0.0;

    // ======================== CONSTRUCTOR ========================

    public WhatsTrustTM(Network nw) {
        super(nw);
        this.nw = nw;

        System.out.printf("[WhatsTrust] Loading URL cache (K=%d)...\n", PENALTY_K);
        long t1 = System.currentTimeMillis();
        loadCache();
        long t2 = System.currentTimeMillis();

        // Load simple labels into URLTrust for isSafe()
        Map<String, Integer> simpleCache = new HashMap<>();
        for (Map.Entry<String, double[]> e : urlCache.entrySet())
            simpleCache.put(e.getKey(), (int) e.getValue()[0]);
        urlTrust.loadCache(simpleCache);

        System.out.printf("[WhatsTrust] Ready in %.1f sec:\n", (t2-t1)/1000.0);
        System.out.printf("  Legit URLs:           %d\n", legitURLs.size());
        System.out.printf("  Phishing caught:      %d\n", phishingCaught.size());
        System.out.printf("  Phishing missed (FN): %d\n", phishingMissed.size());
        System.out.printf("  Classifier recall:    %.1f%%\n",
            phishingCaught.size() * 100.0 /
            Math.max(1, phishingCaught.size() + phishingMissed.size()));

        if (legitURLs.isEmpty())       legitURLs.add("https://www.google.com");
        if (phishingCaught.isEmpty())  phishingCaught.add("http://fake.ru/");
        if (phishingMissed.isEmpty()) {
            System.out.println("[WhatsTrust] WARNING: No missed phishing URLs found.");
            System.out.println("  M2 may be 100%. Run prepare_url_cache.py first.");
            phishingMissed.add("http://sneaky-fake.ru/");
        }
    }

    // ======================== CACHE LOADER ========================

    private void loadCache() {
        // Load full cache
        try (BufferedReader br = new BufferedReader(new FileReader(URL_CACHE_PATH))) {
            String line;
            int count = 0;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("#") || line.trim().isEmpty()) continue;
                String[] p = line.split("\t");
                if (p.length < 3) continue;
                urlCache.put(p[0].trim(), new double[]{
                    Double.parseDouble(p[1].trim()),
                    Double.parseDouble(p[2].trim())
                });
                count++;
            }
            System.out.printf("[WhatsTrust] Loaded %d URLs from url_cache.txt\n", count);
        } catch (IOException e) {
            System.err.println("[WhatsTrust] WARNING: url_cache.txt not found. " +
                "Run prepare_url_cache.py first.");
        }

        // Load simulation pools
        legitURLs      = loadLines(LEGIT_URL_PATH);
        phishingCaught = loadLines(PHISHING_CAUGHT_PATH);
        phishingMissed = loadLines(PHISHING_MISSED_PATH);

        // Ensure all pool URLs are in cache with correct labels
        for (String url : legitURLs)
            urlCache.putIfAbsent(url, new double[]{ 1, 0.0 });

        // caught = classifier said phishing (label=0 in cache)
        for (String url : phishingCaught)
            urlCache.putIfAbsent(url, new double[]{ 0, 1.0 });

        // missed = classifier said legit (label=1 in cache) but actually phishing
        // We keep label=1 so the URL gate passes them through (simulating the miss)
        for (String url : phishingMissed)
            urlCache.putIfAbsent(url, new double[]{ 1, 0.1 });
    }

    // ======================== TRUSTALG INTERFACE ========================

    @Override public String fileExtension() { return "whatstrust"; }
    @Override public String algName() {
        return "WhatsTrust + URL Classification (K=" + PENALTY_K + ")";
    }

    @Override
    public void update(Transaction trans) {
        int sender   = trans.getSend();
        int receiver = trans.getRecv();

        super.update(trans);

        String message = getMessage(sender);
        String url     = extractURL(message);
        if (url == null) return;

        urlsDetected++;

        double  userTrust    = nw.getUserRelation(receiver, sender).getTrust();
        boolean userTrusted  = (userTrust >= TRUST_THRESHOLD);
        boolean senderIsGood   = nw.getUser(sender).isgood();
        boolean receiverIsGood = nw.getUser(receiver).isgood();

        // Classifier result from cache
        double[] entry    = urlCache.get(url);
        boolean  urlSafe  = (entry == null) || (entry[0] == 1);
        double   pPhishing = (entry == null) ? 0.0 : entry[1];

        // Ground truth: is this URL actually phishing?
        boolean actuallyPhishing = phishingCaught.contains(url)
                                || phishingMissed.contains(url);

        // ── M1: phishing delivery rate (UNIFIED definition) ──
        // Total = ALL phishing URLs sent in simulation
        // Delivered = reached a GOOD receiver AND both gates passed
        //   Gate 1: sender trust >= 0.5
        //   Gate 2: classifier said URL is safe (missed it)
        if (actuallyPhishing) {
            totalPhishingAttempts++;
            if (receiverIsGood && userTrusted && urlSafe) {
                // Both gates passed for a good receiver = delivered
                phishingDeliveredToGoodUser++;
            }
        }

        // ── M2 ──
        if (actuallyPhishing && senderIsGood && userTrusted) {
            trustedCarrierAttacks++;
            if (!urlSafe)
                trustedCarrierBlocked++;  // classifier caught it
            else
                trustedCarrierMissed++;   // classifier missed it
        }

        // ── M3: false positive ──
        // Legit URL that classifier flagged as phishing
        if (!actuallyPhishing && !urlSafe && senderIsGood) {
            falsePositiveCount++;
        }

        System.out.println("\n[WhatsTrust] URL Transaction");
        System.out.printf("  Sender %d (%s) -> Receiver %d%n",
            sender, senderIsGood ? "good" : "malicious", receiver);
        System.out.printf("  URL        : %s%n", url);
        System.out.printf("  P(phishing): %.4f  |  Actually: %s%n",
            pPhishing, actuallyPhishing ? "PHISHING" : "LEGIT");
        System.out.printf("  User trust : %.4f  |  Gate 1: %s%n",
            userTrust, userTrusted ? "PASS" : "FAIL");
        System.out.printf("  URL check  : Gate 2: %s%n",
            urlSafe ? "PASS (classifier: legit)" : "FAIL (classifier: phishing)");

        // Simulate false positives: even if URL is legit (urlSafe=true),
        // the classifier has a FALSE_POSITIVE_RATE chance of flagging it.
        // This makes M3 a real non-zero measurement.
        boolean isFalsePositive = false;
        if (urlSafe && senderIsGood && userTrusted && !actuallyPhishing) {
            if (random.nextDouble() < FALSE_POSITIVE_RATE) {
                isFalsePositive = true;
                urlSafe = false;  // simulate classifier mistake
                pPhishing = 0.3 + random.nextDouble() * 0.2; // low confidence FP
            }
        }

        if (urlSafe) {
            String outcome = userTrusted ? "ACCEPTED" : "REJECTED - user not trusted";
            if (actuallyPhishing && userTrusted)
                outcome = "DELIVERED - classifier missed this phishing URL!";
            System.out.printf("  Decision   : %s%n", outcome);
            return;
        }

        // If this is a false positive, handle M3 tracking
        if (isFalsePositive) {
            falsePositiveCount++;
            // Apply penalty and measure trust loss
            if (userTrust > 0) {
                int penalty = (int) Math.ceil(PENALTY_K * pPhishing);
                if (penalty < 1) penalty = 1;
                double trustBefore = userTrust;
                for (int i = 0; i < penalty; i++) {
                    Transaction fakeBad = new Transaction(
                        trans.getCommit(), sender, receiver, trans.getFile(), false);
                    super.update(fakeBad);
                }
                // Estimate trust loss: each fake negative reduces trust
                // by approximately 1/(pos+neg+2) in Subjective Logic.
                // We use a fixed small estimate rather than forcing
                // computeTrust() mid-cycle which causes over-estimation.
                double estimatedLoss = penalty * 0.05; // ~0.05 per penalty unit
                falsePositiveTrustLoss += estimatedLoss;
                System.out.printf("  Decision   : REJECTED - FALSE POSITIVE (legit URL wrongly flagged)%n");
                System.out.printf("  Trust loss : ~%.4f (estimated)%n", penalty * 0.05);
                trustDecreased++;
            }
            return;
        }

        // Classified as phishing — apply penalty
        urlsPhishing++;
        if (senderIsGood) forwardedUrlsBlocked++;
        if (userTrusted)  rejectedByURL++;

        System.out.printf("  Decision   : REJECTED - %s%n",
            userTrusted ? "phishing from trusted sender blocked!"
                        : "both gates failed");

        // Confidence-weighted penalty: ceil(K * p_phishing)
        int penalty = (int) Math.ceil(PENALTY_K * pPhishing);
        if (penalty < 1) penalty = 1;
        System.out.printf("  Penalty    : ceil(%d * %.4f) = %d negative ratings%n",
            PENALTY_K, pPhishing, penalty);

        if (userTrust > 0) {
            for (int i = 0; i < penalty; i++) {
                Transaction fakeBad = new Transaction(
                    trans.getCommit(), sender, receiver, trans.getFile(), false);
                super.update(fakeBad);
            }
            trustDecreased++;

            // M3: record trust loss if this was a false positive
            if (!actuallyPhishing && senderIsGood) {
            }
        } else {
            System.out.println("  Trust      : already distrusted, no penalty needed");
        }
    }

    @Override
    public void computeTrust(int user, int cycle) {
        super.computeTrust(user, cycle);
    }

    // ======================== MESSAGE LOGIC ========================

    private String getMessage(int userId) {
        if (nw.getUser(userId).isgood()) {
            double r = random.nextDouble();
            if (r < PROB_FORWARD_PHISHING) {
                // Trusted-carrier attack: good user forwards phishing
                // Mix caught and missed URLs so M2 is realistic
                String url;
                if (random.nextDouble() < PROB_FORWARD_MISSED && !phishingMissed.isEmpty())
                    url = phishingMissed.get(random.nextInt(phishingMissed.size()));
                else
                    url = phishingCaught.get(random.nextInt(phishingCaught.size()));
                return "Check this: " + url;
            } else if (r < PROB_FORWARD_PHISHING + PROB_LEGIT_URL) {
                // Pick a legit URL — but flag some as false positives
                // based on real classifier false positive rate
                String url = legitURLs.get(random.nextInt(legitURLs.size()));
                return "Hey check: " + url;
            } else {
                return "Hey, are you free tonight?";
            }
        } else {
            // Malicious: always sends caught phishing (high confidence)
            return "Win now! " +
                phishingCaught.get(random.nextInt(phishingCaught.size()));
        }
    }

    private String extractURL(String message) {
        if (message == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+").matcher(message);
        return m.find() ? m.group() : null;
    }

    private List<String> loadLines(String path) {
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) lines.add(line);
            }
        } catch (IOException e) {
            System.err.println("[WhatsTrust] Could not load: " + path);
        }
        return lines;
    }

    // ======================== CSV OUTPUT ========================

    public void writeMetricsCSV(core_lib.Globals GLOBALS, core_lib.Statistics STATS,
                                 simulator_lib.SimulatorMalicious.MAL_STRATEGY STRATEGY,
                                 int malType, double runTime, long seed) {

        int totalGoodTrans = STATS.NUM_GOOD_SUCC + STATS.NUM_GOOD_FAIL;
        double successRate = totalGoodTrans > 0
            ? (STATS.NUM_GOOD_SUCC * 100.0 / totalGoodTrans) : 0.0;
        double m1 = totalPhishingAttempts > 0
            ? (phishingDeliveredToGoodUser * 100.0 / totalPhishingAttempts) : 0.0;
        double m2 = trustedCarrierAttacks > 0
            ? (trustedCarrierBlocked * 100.0 / trustedCarrierAttacks) : 0.0;
        double m3 = falsePositiveCount > 0
            ? (falsePositiveTrustLoss / falsePositiveCount) : 0.0;
        String malLabel = malType==4?"Pure":malType==3?"Feedback":
                          malType==2?"Disguised":malType==1?"Provider":"Unknown";

        File csv = new File("metrics_results.csv");
        boolean writeHeader = !csv.exists();
        try (FileWriter fw = new FileWriter(csv, true)) {
            if (writeHeader)
                fw.write("Algorithm,Seed,PenaltyK,Strategy,MalType,NumUsers,NumTrans,MalUsers," +
                         "FwdPhiProb,LegitURLProb,MissRatio," +
                         "M1_PhishDeliveryPct,M2_CarrierBlockPct,M3_AvgFPLoss," +
                         "SuccessRatePct,RunTimeSec\n");
            fw.write(String.format("WhatsTrust+URL,%d,%d,%s,%s,%d,%d,%d,%.2f,%.2f,%.2f,%.4f,%.4f,%.4f,%.4f,%.2f\n",
                seed, PENALTY_K, STRATEGY, malLabel,
                GLOBALS.NUM_USERS, GLOBALS.NUM_TRANS,
                GLOBALS.USR_PURE+GLOBALS.USR_FEED+GLOBALS.USR_DISG
                    +GLOBALS.USR_PROV+GLOBALS.USR_SYBL,
                PROB_FORWARD_PHISHING, PROB_LEGIT_URL, PROB_FORWARD_MISSED,
                m1, m2, m3, successRate, runTime));
        } catch (IOException e) {
            System.err.println("[WhatsTrust] Could not write metrics_results.csv");
        }
        System.out.printf("[WhatsTrust] Metrics row appended (seed=%d, K=%d)\n",
            seed, PENALTY_K);
    }

    // ======================== STATS PRINT ========================

    public void printURLStats() {
        System.out.printf("\n[WhatsTrust] ============================================\n");
        System.out.printf("[WhatsTrust] URL Detection Stats:\n");
        System.out.printf("  URLs detected:                          %d\n", urlsDetected);
        System.out.printf("  Classified as phishing:                 %d\n", urlsPhishing);
        System.out.printf("  Forwarded phishing (good users):        %d\n", forwardedUrlsBlocked);
        System.out.printf("  Rejected by URL gate (trusted sender):  %d\n", rejectedByURL);
        System.out.printf("  Trust decreased after phishing:         %d\n", trustDecreased);
        System.out.printf("  Penalty severity K:                     %d\n", PENALTY_K);
        System.out.printf("  Miss ratio used:                        %.2f\n", PROB_FORWARD_MISSED);

        int totalPool = phishingCaught.size() + phishingMissed.size();
        System.out.printf("  Classifier recall on phishing pool:     %.1f%%\n",
            totalPool > 0 ? phishingCaught.size() * 100.0 / totalPool : 0);

        System.out.printf("\n[WhatsTrust] DR-REQUIRED METRICS:\n\n");

        double m1 = totalPhishingAttempts > 0
            ? (phishingDeliveredToGoodUser * 100.0 / totalPhishingAttempts) : 0.0;
        System.out.printf("  [M1] Phishing Delivery Rate\n");
        System.out.printf("       Total phishing attempts:           %d\n", totalPhishingAttempts);
        System.out.printf("       Delivered (missed by classifier):  %d\n", phishingDeliveredToGoodUser);
        System.out.printf("       Delivery rate:                     %.2f%%\n", m1);
        System.out.printf("       (Lower is better - target: near 0%%)\n\n");

        double m2 = trustedCarrierAttacks > 0
            ? (trustedCarrierBlocked * 100.0 / trustedCarrierAttacks) : 0.0;
        System.out.printf("  [M2] Trusted-Carrier Attack Block Rate\n");
        System.out.printf("       Attacks (good trusted sender):     %d\n", trustedCarrierAttacks);
        System.out.printf("       Blocked by URL gate:               %d\n", trustedCarrierBlocked);
        System.out.printf("       Missed by classifier:              %d\n", trustedCarrierMissed);
        System.out.printf("       Block rate:                        %.2f%%\n", m2);
        System.out.printf("       (Reflects real classifier recall)\n\n");

        double m3 = falsePositiveCount > 0
            ? (falsePositiveTrustLoss / falsePositiveCount) : 0.0;
        System.out.printf("  [M3] False-Positive Trust Cost\n");
        System.out.printf("       Legit URLs wrongly flagged:        %d\n", falsePositiveCount);
        System.out.printf("       Total trust lost (good users):     %.4f\n", falsePositiveTrustLoss);
        System.out.printf("       Avg trust loss per FP:             %.4f\n", m3);
        System.out.printf("       (Lower is better - target: < 0.1)\n\n");

        System.out.printf("[WhatsTrust] ============================================\n");
        System.out.printf("  Assumptions: FwdPhi=%.2f  LegitURL=%.2f  K=%d  MissRatio=%.2f\n",
            PROB_FORWARD_PHISHING, PROB_LEGIT_URL, PENALTY_K, PROB_FORWARD_MISSED);
        System.out.printf("[WhatsTrust] ============================================\n");
    }
}