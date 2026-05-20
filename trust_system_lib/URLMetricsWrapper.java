package trust_system_lib;

import core_lib.*;
import java.io.*;
import java.util.*;

/**
 * URLMetricsWrapper.java
 * -----------------------
 * Wraps any TrustAlg (EigenTrust, TNA-SL, original WhatsTrust)
 * and tracks M1/M2/M3 metrics WITHOUT adding a URL gate.
 *
 * M1 (Phishing Delivery Rate):
 *   Counts phishing URLs that reached a good receiver where the
 *   sender's trust was >= 0.5 (Gate 1 passed). If the trust
 *   algorithm already flagged the sender as low trust, the message
 *   would be rejected even without a URL gate — so those don't count.
 *   This gives a REAL M1 that reflects actual algorithm performance.
 *
 * M2 (Trusted-Carrier Block Rate):
 *   Counts phishing from good trusted senders (trust >= 0.5) to
 *   good receivers. Always 0% blocked — no URL gate exists.
 *
 * M3: N/A — no classifier means no false positives possible.
 */
public class URLMetricsWrapper implements TrustAlg {

    private static final String LEGIT_URL_PATH       = "test_legit_urls.txt";
    private static final String PHISHING_CAUGHT_PATH = "phishing_caught.txt";
    private static final String PHISHING_MISSED_PATH = "phishing_missed.txt";

    public static double PROB_FORWARD_PHISHING = 0.10;
    public static double PROB_LEGIT_URL        = 0.20;
    public static double PROB_FORWARD_MISSED   = 0.061;

    static {
        String fwd  = System.getProperty("fwdPhiProb");
        String leg  = System.getProperty("legitURLProb");
        String miss = System.getProperty("missRatio");
        if (fwd  != null) PROB_FORWARD_PHISHING = Double.parseDouble(fwd);
        if (leg  != null) PROB_LEGIT_URL        = Double.parseDouble(leg);
        if (miss != null) PROB_FORWARD_MISSED   = Double.parseDouble(miss);
    }

    private final TrustAlg wrapped;
    private final Network  nw;
    private final Random   random = new Random();

    private List<String> legitURLs          = new ArrayList<>();
    private List<String> phishingCaughtList = new ArrayList<>();
    private List<String> phishingMissedList = new ArrayList<>();
    private Set<String>  phishingAllURLs    = new HashSet<>();

    // M1 fields (unified definition — same as W+U)
    private int totalPhishingAttempts       = 0;  // ALL phishing URLs sent
    private int phishingBlockedByTrust      = 0;  // blocked by trust layer
    private int phishingDeliveredToGoodUser = 0;  // delivered to good receiver

    // M2: trusted-carrier attacks
    private int trustedCarrierAttacks = 0;
    private int trustedCarrierMissed  = 0;  // always = attacks (no URL gate)

    public URLMetricsWrapper(TrustAlg wrapped, Network nw) {
        this.wrapped = wrapped;
        this.nw      = nw;

        legitURLs          = loadLines(LEGIT_URL_PATH);
        phishingCaughtList = loadLines(PHISHING_CAUGHT_PATH);
        phishingMissedList = loadLines(PHISHING_MISSED_PATH);
        phishingAllURLs.addAll(phishingCaughtList);
        phishingAllURLs.addAll(phishingMissedList);

        if (legitURLs.isEmpty())
            legitURLs.add("https://www.google.com");
        if (phishingCaughtList.isEmpty())
            phishingCaughtList.add("http://fake.ru/");
        if (phishingMissedList.isEmpty())
            phishingMissedList.add("http://sneaky-fake.ru/");

        System.out.printf("[URLMetrics] Wrapping %s with URL metrics tracking.\n",
            wrapped.algName());
        System.out.printf("  Legit URLs:      %d\n", legitURLs.size());
        System.out.printf("  Phishing caught: %d\n", phishingCaughtList.size());
        System.out.printf("  Phishing missed: %d\n", phishingMissedList.size());
    }

    @Override public String fileExtension() { return wrapped.fileExtension(); }
    @Override public String algName() { return wrapped.algName() + " (no URL gate)"; }

    @Override
    public void update(Transaction trans) {
        int sender   = trans.getSend();
        int receiver = trans.getRecv();

        // Step 1: run wrapped algorithm normally
        wrapped.update(trans);

        // Step 2: assign message
        String message = getMessage(sender);
        String url     = extractURL(message);
        if (url == null) return;

        boolean senderIsGood   = nw.getUser(sender).isgood();
        boolean receiverIsGood = nw.getUser(receiver).isgood();
        boolean actuallyPhishing = phishingAllURLs.contains(url);

        // Use relative trust threshold: sender is "trusted" if their trust
        // is above the average trust of all users in the network.
        // This is necessary because EigenTrust and TNA-SL use different
        // trust scales (EigenTrust values sum to 1.0, so individual values
        // are ~1/N which is far below the WhatsTrust threshold of 0.5).
        double senderTrust = nw.getUserRelation(receiver, sender).getTrust();
        double avgTrust = 0.0;
        int numUsers = nw.GLOBALS.NUM_USERS;
        for (int i = 0; i < numUsers; i++)
            avgTrust += nw.getUserRelation(receiver, i).getTrust();
        avgTrust /= numUsers;
        // Sender is trusted if their trust is above average
        boolean senderTrusted = (senderTrust > avgTrust);

        // ── M1: phishing delivery rate (UNIFIED definition) ──
        // Total = ALL phishing URLs sent in simulation (any sender, any receiver)
        // Delivered = reached a GOOD receiver AND sender was trusted
        // This matches W+U's M1 definition exactly — same denominator.
        if (actuallyPhishing) {
            totalPhishingAttempts++;  // count every phishing URL sent
            if (receiverIsGood && senderTrusted) {
                // Trust layer passed (sender above avg) + good receiver
                // = delivered. No URL gate to provide second check.
                phishingDeliveredToGoodUser++;
            }
        }

        // ── M2: trusted-carrier attack ──
        // Good user with above-average trust forwarding phishing to good receiver
        if (actuallyPhishing && senderIsGood && senderTrusted && receiverIsGood) {
            trustedCarrierAttacks++;
            trustedCarrierMissed++;
        }
    }

    @Override
    public void computeTrust(int user, int cycle) {
        wrapped.computeTrust(user, cycle);
    }

    private String getMessage(int userId) {
        if (nw.getUser(userId).isgood()) {
            double r = random.nextDouble();
            if (r < PROB_FORWARD_PHISHING) {
                String url;
                if (random.nextDouble() < PROB_FORWARD_MISSED
                        && !phishingMissedList.isEmpty())
                    url = phishingMissedList.get(
                        random.nextInt(phishingMissedList.size()));
                else
                    url = phishingCaughtList.get(
                        random.nextInt(phishingCaughtList.size()));
                return "Check this: " + url;
            } else if (r < PROB_FORWARD_PHISHING + PROB_LEGIT_URL) {
                return "Hey check: " +
                    legitURLs.get(random.nextInt(legitURLs.size()));
            } else {
                return "Hey, are you free tonight?";
            }
        } else {
            return "Win now! " +
                phishingCaughtList.get(random.nextInt(phishingCaughtList.size()));
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
            System.err.println("[URLMetrics] Could not load: " + path);
        }
        return lines;
    }

    public void printURLStats() {
        System.out.printf("\n[URLMetrics] ============================================\n");
        System.out.printf("[URLMetrics] Baseline Metrics (%s):\n", wrapped.algName());

        double m1 = totalPhishingAttempts > 0
            ? (phishingDeliveredToGoodUser * 100.0 / totalPhishingAttempts) : 0.0;
        double trustBlockRate = totalPhishingAttempts > 0
            ? (phishingBlockedByTrust * 100.0 / totalPhishingAttempts) : 0.0;

        System.out.printf("\n  [M1] Phishing Delivery Rate\n");
        System.out.printf("       Total phishing attempts (all):    %d\n", totalPhishingAttempts);

        System.out.printf("       Delivered to good receiver:        %d\n",
            phishingDeliveredToGoodUser);
        System.out.printf("       Delivery rate (M1):               %.2f%%\n", m1);
        System.out.printf("       (W+U achieves ~1%% using URL gate)\n\n");

        double m2 = trustedCarrierAttacks > 0
            ? (0.0) : 0.0;
        System.out.printf("  [M2] Trusted-Carrier Attack Block Rate\n");
        System.out.printf("       Attacks attempted:                %d\n", trustedCarrierAttacks);
        System.out.printf("       Blocked:                          0 (no URL gate)\n");
        System.out.printf("       Block rate (M2):                  0.00%%\n");
        System.out.printf("       (W+U achieves ~93%% using URL gate)\n\n");

        System.out.printf("  [M3] False-Positive Trust Cost:  N/A (no classifier)\n\n");
        System.out.printf("[URLMetrics] ============================================\n");
    }

    public void writeMetricsCSV(core_lib.Globals GLOBALS, core_lib.Statistics STATS,
                                 simulator_lib.SimulatorMalicious.MAL_STRATEGY STRATEGY,
                                 int malType, double runTime, long seed) {

        int totalGoodTrans = STATS.NUM_GOOD_SUCC + STATS.NUM_GOOD_FAIL;
        double successRate = totalGoodTrans > 0
            ? (STATS.NUM_GOOD_SUCC * 100.0 / totalGoodTrans) : 0.0;
        double m1 = totalPhishingAttempts > 0
            ? (phishingDeliveredToGoodUser * 100.0 / totalPhishingAttempts) : 0.0;
        String malLabel = malType==4?"Pure":malType==3?"Feedback":
                          malType==2?"Disguised":malType==1?"Provider":"Unknown";

        File csv = new File("metrics_results.csv");
        boolean writeHeader = !csv.exists();
        try (FileWriter fw = new FileWriter(csv, true)) {
            if (writeHeader)
                fw.write("Algorithm,Seed,Strategy,MalType,NumUsers,NumTrans,MalUsers," +
                         "FwdPhiProb,LegitURLProb,MissRatio," +
                         "M1_PhishDeliveryPct,M2_CarrierBlockPct,M3_AvgFPLoss," +
                         "SuccessRatePct,RunTimeSec\n");
            fw.write(String.format(
                "%s,%d,%s,%s,%d,%d,%d,%.2f,%.2f,%.2f,%.4f,%.4f,%.4f,%.4f,%.2f\n",
                wrapped.algName(), seed, STRATEGY, malLabel,
                GLOBALS.NUM_USERS, GLOBALS.NUM_TRANS,
                GLOBALS.USR_PURE+GLOBALS.USR_FEED+GLOBALS.USR_DISG
                    +GLOBALS.USR_PROV+GLOBALS.USR_SYBL,
                PROB_FORWARD_PHISHING, PROB_LEGIT_URL, PROB_FORWARD_MISSED,
                m1, 0.0, 0.0, successRate, runTime));
        } catch (IOException e) {
            System.err.println("[URLMetrics] Could not write metrics_results.csv");
        }
        System.out.printf("[URLMetrics] Metrics row written (seed=%d)\n", seed);
    }
}