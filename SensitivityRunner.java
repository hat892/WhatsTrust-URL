/**
 * SensitivityRunner.java
 * -----------------------
 * Runs the simulation multiple times across different assumption values
 * so you can justify why you chose PROB_FORWARD_PHISHING = 0.10 and
 * PROB_LEGIT_URL = 0.20  (addresses Dr's Issue 5c).
 *
 * HOW TO USE:
 *   1. Replace your main simulation entry point with this class,
 *      or call runSensitivityAnalysis() from your existing main().
 *   2. The output prints a table you can paste directly into your paper.
 *
 * WHAT IT DOES:
 *   For each combination of (PROB_FORWARD_PHISHING, PROB_LEGIT_URL),
 *   it runs TRIALS_PER_CONFIG independent trials with different random
 *   seeds, collects M1/M2/M3 + success rate, and prints mean ± std-dev.
 *
 * IMPORTANT: Your simulator's main loop must call
 *   WhatsTrustTM.PROB_FORWARD_PHISHING and WhatsTrustTM.PROB_LEGIT_URL
 *   (which are now public static fields) each time it constructs the
 *   WhatsTrustTM object, so this runner can change them between trials.
 */
public class SensitivityRunner {

    // ── Assumption values to sweep (Issue 5c) ──
    static final double[] FWD_PHISHING_VALS = { 0.05, 0.10, 0.20 };
    static final double[] LEGIT_URL_VALS    = { 0.10, 0.20, 0.30 };

    // ── Number of independent trials per configuration ──
    // Dr's feedback (Issue 5a): run 5-10 times with different seeds
    static final int TRIALS_PER_CONFIG = 7;

    /**
     * Call this from your main() instead of (or after) a single run.
     * Replace runOneSimulation() with a call to your actual simulation
     * entry point, parameterised by the random seed.
     */
    public static void runSensitivityAnalysis() {

        System.out.println("\n=== SENSITIVITY ANALYSIS ===");
        System.out.printf("%-8s %-10s %-6s | %-22s %-22s %-22s %-20s%n",
            "FwdPhi", "LegitURL", "Trial",
            "M1-PhishDelivery%", "M2-CarrierBlock%", "M3-AvgFPLoss", "SuccessRate%");
        System.out.println("-".repeat(110));

        for (double fwd : FWD_PHISHING_VALS) {
            for (double legit : LEGIT_URL_VALS) {

                // Set assumption parameters on the shared static fields
                trust_system_lib.WhatsTrustTM.PROB_FORWARD_PHISHING = fwd;
                trust_system_lib.WhatsTrustTM.PROB_LEGIT_URL        = legit;

                double[] m1 = new double[TRIALS_PER_CONFIG];
                double[] m2 = new double[TRIALS_PER_CONFIG];
                double[] m3 = new double[TRIALS_PER_CONFIG];
                double[] sr = new double[TRIALS_PER_CONFIG];

                for (int trial = 0; trial < TRIALS_PER_CONFIG; trial++) {
                    long seed = 1000L + trial;   // deterministic, reproducible seeds

                    // ── Replace this call with your real simulation ──
                    // SimulationResult result = YourSimulator.run(seed);
                    // m1[trial] = result.phishingDeliveryRate;
                    // m2[trial] = result.carrierBlockRate;
                    // m3[trial] = result.avgFalsePositiveLoss;
                    // sr[trial] = result.successRate;
                    //
                    // Placeholder values (remove once integrated):
                    m1[trial] = 0.0;
                    m2[trial] = 0.0;
                    m3[trial] = 0.0;
                    sr[trial] = 0.0;

                    System.out.printf("%-8.2f %-10.2f %-6d | %-22.4f %-22.4f %-22.4f %-20.4f%n",
                        fwd, legit, trial + 1, m1[trial], m2[trial], m3[trial], sr[trial]);
                }

                // Print mean ± std-dev for this configuration
                System.out.printf("%-8.2f %-10.2f %-6s | %-22s %-22s %-22s %-20s%n",
                    fwd, legit, "AVG",
                    String.format("%.4f±%.4f", mean(m1), stddev(m1)),
                    String.format("%.4f±%.4f", mean(m2), stddev(m2)),
                    String.format("%.4f±%.4f", mean(m3), stddev(m3)),
                    String.format("%.4f±%.4f", mean(sr), stddev(sr)));
                System.out.println("-".repeat(110));
            }
        }

        System.out.println("\n=== END SENSITIVITY ANALYSIS ===");
        System.out.println("Paste the AVG rows into Table X of your paper.");
        System.out.println("If results are stable across FwdPhi/LegitURL, your assumption choice is justified.");
    }

    // ── Statistics helpers ──

    private static double mean(double[] vals) {
        double sum = 0;
        for (double v : vals) sum += v;
        return sum / vals.length;
    }

    private static double stddev(double[] vals) {
        double m = mean(vals);
        double sum = 0;
        for (double v : vals) sum += (v - m) * (v - m);
        return Math.sqrt(sum / vals.length);
    }
}
