import java.io.*;
import core_lib.*;
import simulator_lib.SimulatorInput;
import simulator_lib.SimulatorOutput;
import simulator_lib.SimulatorUtils;
import simulator_lib.SimulatorMalicious;
import trust_system_lib.*;

/**
 * TraceSimulator  —  updated for multi-trial sensitivity analysis.
 *
 * New argument (optional):
 *   -seed <long>   Random seed for this run. Default: system time.
 *                  Used by run_sensitivity.bat to run the same trace
 *                  multiple times with different seeds.
 *
 * Everything else is identical to the original.
 */
public class TraceSimulator {

    private enum TSYS { NONE, EIGEN, ET_INC, TNA_SL, Socialtrust, Maimona, WHATSTRUST }

    private static String FILE_NAME;
    private static TrustAlg TALG;
    private static TSYS TSYSTEM;
    private static SimulatorMalicious.MAL_STRATEGY STRATEGY;
    private static long RAND_SEED = -1;   // -1 means "use system time"

    public static void main(String[] args) throws IOException {

        long start_time = System.currentTimeMillis();
        parse_arguments(args);

        // Apply seed before anything random happens
        // Globals picks up RAND_SEED in its constructor when it is >= 0
        SimulatorInput Trace = new SimulatorInput(FILE_NAME);
        Globals GLOBALS = Trace.parseGlobals();

        // Override the random seed if one was supplied on the command line
        if (RAND_SEED >= 0) {
            GLOBALS.RAND.setSeed(RAND_SEED);
        }

        Network nw = new Network(GLOBALS);
        Trace.parseUsers(nw);
        Trace.parseLibraries(nw);
        System.out.print("\nTrace file parsed and static initialization complete...\n");

        SimulatorMalicious mal = new SimulatorMalicious(nw, STRATEGY);

        String trustALG = "";
        if (TSYSTEM == TSYS.EIGEN) {
            TALG = new URLMetricsWrapper(new EigenTM(nw), nw);
            trustALG = "eigen";
        } else if (TSYSTEM == TSYS.ET_INC) {
            TALG = new URLMetricsWrapper(new EtIncTM(nw), nw);
            trustALG = "ET_INC";
        } else if (TSYSTEM == TSYS.TNA_SL) {
            TALG = new URLMetricsWrapper(new TnaSlTM(nw), nw);
            trustALG = "TNA_SL";
        } else if (TSYSTEM == TSYS.Socialtrust) {
            TALG = new URLMetricsWrapper(new Socialtrust(nw), nw);
            trustALG = "socialtrust";
        } else if (TSYSTEM == TSYS.Maimona) {
            TALG = new URLMetricsWrapper(new Socialtrust(nw), nw);
            trustALG = "Maimona";
        } else if (TSYSTEM == TSYS.WHATSTRUST) {
            TALG = new WhatsTrustTM(nw);  trustALG = "WhatsTrust";
        } else {
            TALG = new NoneTM(nw);        trustALG = "None";
        }

        // Warm-up phase
        System.out.printf("Beginning warm-up phase... (%d transactions)\n", GLOBALS.WARMUP);
        SimulatorUtils Simulate = new SimulatorUtils();
        for (int i = 0; i < GLOBALS.WARMUP; i++) {
            Simulate.simTrans(nw, i, Trace.parseNextTransaction(), mal, TALG);
            if ((i % 500 == 0) && (i != 0)) {
                System.out.printf("Warm-up transactions completed: %d...\n", i);
                System.out.flush();
            }
        }
        System.out.print("Warm-up phase complete...\n");

        // Simulation phase
        nw.STATS.reset();
        System.out.printf("Beginning simulation phase... (%d transactions)\n", GLOBALS.NUM_TRANS);
        for (int i = GLOBALS.WARMUP; i < (GLOBALS.WARMUP + GLOBALS.NUM_TRANS); i++) {
            Simulate.simTrans(nw, i, Trace.parseNextTransaction(), mal, TALG);
            if (((i - GLOBALS.WARMUP) % 500 == 0) && (i != 0)) {
                System.out.printf("Transactions completed so far: %d...\n", (i - GLOBALS.WARMUP));
                System.out.flush();
            }
        }
        System.out.printf("Simulation phase complete...\n");
        Simulate.commitRemaining(nw, GLOBALS.WARMUP + GLOBALS.NUM_TRANS, TALG);

        // Output
        FILE_NAME = FILE_NAME.substring(0, FILE_NAME.lastIndexOf('.') + 1);
        FILE_NAME = FILE_NAME.concat(TALG.fileExtension());
        SimulatorOutput Output = new SimulatorOutput(FILE_NAME);
        Output.printHeader(GLOBALS, Trace.getGenSeed(), TALG, STRATEGY);
        Output.printStatistics(nw.GLOBALS, nw.STATS);

        long stop_time = System.currentTimeMillis();
        double run_time = ((stop_time - start_time) / 1000.0);
        System.out.printf("Run complete! Data written to %s\n", FILE_NAME);
        System.out.printf("Simulation runtime: %f secs\n\n", run_time);

        int malType = 0;
        if (nw.GLOBALS.USR_FEED == 0 && nw.GLOBALS.USR_DISG == 0 && nw.GLOBALS.USR_PROV == 0)
            malType = 4;
        else if (nw.GLOBALS.USR_PURE == 0 && nw.GLOBALS.USR_DISG == 0 && nw.GLOBALS.USR_PROV == 0)
            malType = 3;
        else if (nw.GLOBALS.USR_PURE == 0 && nw.GLOBALS.USR_FEED == 0 && nw.GLOBALS.USR_PROV == 0)
            malType = 2;
        else if (nw.GLOBALS.USR_PURE == 0 && nw.GLOBALS.USR_FEED == 0 && nw.GLOBALS.USR_DISG == 0)
            malType = 1;

        // Write standard CSV row
        Output.writeResultsCSV(GLOBALS, nw.STATS, STRATEGY, malType, run_time, trustALG);

        // Print and write metrics for WhatsTrust+URL
        if (TSYSTEM == TSYS.WHATSTRUST) {
            WhatsTrustTM wt = (WhatsTrustTM) TALG;
            wt.printURLStats();
            wt.writeMetricsCSV(GLOBALS, nw.STATS, STRATEGY, malType, run_time, RAND_SEED);
        }

        // Print and write metrics for baseline algorithms (wrapped with URLMetricsWrapper)
        if (TSYSTEM == TSYS.EIGEN || TSYSTEM == TSYS.TNA_SL
                || TSYSTEM == TSYS.Socialtrust || TSYSTEM == TSYS.ET_INC
                || TSYSTEM == TSYS.Maimona) {
            URLMetricsWrapper wrapper = (URLMetricsWrapper) TALG;
            wrapper.printURLStats();
            wrapper.writeMetricsCSV(GLOBALS, nw.STATS, STRATEGY, malType, run_time, RAND_SEED);
        }

        Trace.shutdown();
        Output.shutdown();
    }

    // ---------------------------------------------------------------

    private static void parse_arguments(String[] args) {
        // Accept 6 args (original) or 8 args (original + -seed <value>)
        if (args.length != 6 && args.length != 8) {
            System.out.print("\nInvalid # of arguments. Aborting.\n\n");
            System.exit(1);
        }

        for (int i = 1; i < args.length; i += 2) {
            if (args[i - 1].equalsIgnoreCase("-input")) {
                FILE_NAME = args[i];
            } else if (args[i - 1].equalsIgnoreCase("-seed")) {
                RAND_SEED = Long.parseLong(args[i]);
            } else if (args[i - 1].equalsIgnoreCase("-tm")) {
                String tm = args[i];
                if      (tm.equalsIgnoreCase("eigen"))       TSYSTEM = TSYS.EIGEN;
                else if (tm.equalsIgnoreCase("eigentrust"))  TSYSTEM = TSYS.EIGEN;
                else if (tm.equalsIgnoreCase("et_inc"))      TSYSTEM = TSYS.ET_INC;
                else if (tm.equalsIgnoreCase("etinc"))       TSYSTEM = TSYS.ET_INC;
                else if (tm.equalsIgnoreCase("tna_sl"))      TSYSTEM = TSYS.TNA_SL;
                else if (tm.equalsIgnoreCase("tnasl"))       TSYSTEM = TSYS.TNA_SL;
                else if (tm.equalsIgnoreCase("socialtrust")) TSYSTEM = TSYS.Socialtrust;
                else if (tm.equalsIgnoreCase("Maimona"))     TSYSTEM = TSYS.Maimona;
                else if (tm.equalsIgnoreCase("whatstrust"))  TSYSTEM = TSYS.WHATSTRUST;
                else                                         TSYSTEM = TSYS.NONE;
            } else if (args[i - 1].equalsIgnoreCase("-strategy")) {
                String st = args[i];
                if      (st.equalsIgnoreCase("isolated"))   STRATEGY = SimulatorMalicious.MAL_STRATEGY.ISOLATED;
                else if (st.equalsIgnoreCase("collective")) STRATEGY = SimulatorMalicious.MAL_STRATEGY.COLLECTIVE;
                else                                        STRATEGY = SimulatorMalicious.MAL_STRATEGY.NAIVE;
            } else {
                System.out.print("\nRequired argument missing. Aborting.\n\n");
                System.exit(1);
            }
        }
    }
}