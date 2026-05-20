package trust_system_lib;

import core_lib.*;
import java.util.*;

/**
 * Socialtrust.java  —  Optimized
 * --------------------------------
 * Original by Fatimah Almuzaini.
 *
 * PERFORMANCE CHANGE (one fix, big impact):
 * -----------------------------------------
 * The original computeTrust() contained a triple nested loop:
 *
 *     for each user i (N)
 *       for each of user's friends x (F)
 *         for each friend-of-friend of x (F)
 *           if i == fof → record path
 *
 * This ran O(N * F²) EVERY TIME computeTrust() was called, which is
 * once per cycle per user.  With N=100 users and F≈20 friends each,
 * that is 100 × 400 = 40,000 inner iterations per user per cycle,
 * or 4,000,000 iterations per cycle across the network — multiplied
 * by however many cycles the simulation runs.
 *
 * FIX: Build the FOF adjacency map ONCE in the constructor and reuse it.
 * fofPaths[user][i] = list of (friend, friend-index, fof-index) tuples
 * needed to compute the discounted opinion chain to reach user i via FOF.
 * After construction, computeTrust() does a simple map lookup.
 *
 * Everything else (formulas, data structures, update logic) is unchanged.
 */
public class Socialtrust implements TrustAlg {

    private Trustinfo[][] LL;
    private globalTrust[] TL;
    private globalTrust[] UL;
    private Network nw;
    private int[][] friends_array;
    private int[][] acq_array;
    private int[][] size;
    private int[][] asize;
    private int NUM_USERS;
    private int random_friend;
    private int user_friend;
    private int p;
    private double pt;
    Random rand = new Random();
    boolean friend_flag;
    boolean acq_flag;
    boolean fof_flag;

    // ------------------------------------------------------------------
    // FOF cache: built once, reused every computeTrust() call.
    // fofPaths[user][target] = list of int[3] = {friendIdx, fIdx, fofIdx}
    //   where:
    //     friendIdx = index into friends_array[user] for the intermediate friend
    //     fIdx      = friends_array[user][friendIdx]  (the actual friend uid)
    //     fofIdx    = index into friends_array[fIdx] where target lives
    // ------------------------------------------------------------------
    private Map<Integer, List<int[]>>[] fofCache;  // fofCache[user] -> target -> paths

    @SuppressWarnings("unchecked")
    public Socialtrust(Network nw) {
        this.nw = nw;
        NUM_USERS = this.nw.GLOBALS.NUM_USERS;
        LL = new Trustinfo[NUM_USERS][NUM_USERS];
        TL = new globalTrust[NUM_USERS];
        UL = new globalTrust[NUM_USERS];
        size  = new int[NUM_USERS][1];
        asize = new int[NUM_USERS][1];
        friends_array = new int[NUM_USERS][NUM_USERS];
        acq_array     = new int[NUM_USERS][NUM_USERS];

        for (int i = 0; i < NUM_USERS; i++) {
            UL[i] = new globalTrust();
            TL[i] = new globalTrust(false);
            asize[i][0] = 0;
            for (int j = 0; j < NUM_USERS; j++) {
                friends_array[i][j] = -1;
                LL[i][j] = new Trustinfo();
            }
            pt = NUM_USERS * 0.2;
            p  = (int) pt;

            user_friend = rand.nextInt(p);
            user_friend = user_friend + p;
            size[i][0]  = user_friend;

            for (int x = 0; x < user_friend; x++) {
                random_friend = rand.nextInt(NUM_USERS);
                while (random_friend == i
                        || isfriend(i, random_friend)
                        || (!this.nw.getUser(random_friend).isgood()))
                    random_friend = rand.nextInt(NUM_USERS);
                friends_array[i][x] = random_friend;
                LL[i][x].addpos();
                UL[random_friend] = new globalTrust();
                UL[random_friend].increaseu();
                UL[random_friend].addwp();
            }
        }

        // ------ Build FOF cache after friendship is fully initialised ------
        fofCache = new HashMap[NUM_USERS];
        buildFOFCache();
    }

    /**
     * Build the FOF lookup table once.
     * Cost: O(N * F²) — paid one time at startup, not every cycle.
     */
    private void buildFOFCache() {
        for (int user = 0; user < NUM_USERS; user++) {
            fofCache[user] = new HashMap<>();
            for (int x = 0; x < size[user][0]; x++) {
                int friendUid = friends_array[user][x];
                if (friendUid < 0) continue;
                for (int j = 0; j < size[friendUid][0]; j++) {
                    int fofUid = friends_array[friendUid][j];
                    if (fofUid < 0 || fofUid == user) continue;
                    // Skip if already a direct friend or acquaintance of user
                    // (those are handled by separate branches in computeTrust)
                    if (isfriend(user, fofUid)) continue;

                    fofCache[user]
                        .computeIfAbsent(fofUid, k -> new ArrayList<>())
                        .add(new int[]{ x, friendUid, j });
                    // int[0] = index into size[user]  (friend slot index)
                    // int[1] = friendUid
                    // int[2] = index into size[friendUid]  (fof slot index)
                }
            }
        }
    }

    // ======================== TRUSTALG INTERFACE ========================

    @Override
    public String fileExtension() { return "socialtrust"; }

    @Override
    public String algName() { return "socialtrust"; }

    @Override
    public void update(Transaction trans) {
        int new_r = trans.getRecv();
        int new_s = trans.getSend();
        double t, wt, p, n;
        int nu;

        if (!isfriend(new_r, new_s)) {
            if (!isacqua(new_r, new_s)) {
                acq_array[new_r][asize[new_r][0]] = new_s;
                asize[new_r][0]++;
                if (trans.getValid())
                    LL[new_r][asize[new_r][0]].addpos();
                else
                    LL[new_r][asize[new_r][0]].addneg();
                if (TL[new_s].state)
                    TL[new_s].increaseu();
                else
                    UL[new_s].increaseu();
            } else {
                for (int i = 0; i < asize[new_r][0]; i++) {
                    if (new_s == acq_array[new_r][i]) {
                        if (trans.getValid()) { LL[new_r][i].addpos(); break; }
                        else                  { LL[new_r][i].addneg(); break; }
                    }
                }
            }
        } else {
            for (int i = 0; i < size[new_r][0]; i++) {
                if (new_s == friends_array[new_r][i]) {
                    if (trans.getValid()) { LL[new_r][i].addpos(); break; }
                    else                  { LL[new_r][i].addneg(); break; }
                }
            }
        }

        if (trans.getValid()) {
            if (UL[new_s].state) {
                UL[new_s].addwp();
                p  = UL[new_s].getwp();
                n  = UL[new_s].getwn();
                nu = UL[new_s].getnumu();
                t  = computet(p, n, nu);
                if (t >= 0.5) { TL[new_s].addele(p, n, nu); UL[new_s].delete(); }
            }
            if (TL[new_s].state) {
                TL[new_s].addwp();
                p  = TL[new_s].getwp();
                n  = TL[new_s].getwn();
                nu = TL[new_s].getnumu();
                t  = computet(p, n, nu);
                if (t < 0.5) { UL[new_s].addele(p, n, nu); TL[new_s].delete(); }
            }
        } else {
            if (UL[new_s].state) {
                UL[new_s].addwn();
                p  = UL[new_s].getwp();
                n  = UL[new_s].getwn();
                nu = UL[new_s].getnumu();
                t  = computet(p, n, nu);
                if (t >= 0.5) { TL[new_s].addele(p, n, nu); UL[new_s].delete(); }
            }
            if (TL[new_s].state) {
                TL[new_s].addwn();
                p  = TL[new_s].getwp();
                n  = TL[new_s].getwn();
                nu = TL[new_s].getnumu();
                t  = computet(p, n, nu);
                if (t < 0.5) { UL[new_s].addele(p, n, nu); TL[new_s].delete(); }
            }
        }
    }

    /**
     * Compute trust for 'user' toward all other users.
     *
     * OPTIMISED: FOF paths are read from fofCache instead of being
     * re-enumerated by triple nested loop every call.
     */
    @Override
    public void computeTrust(int user, int cycle) {
        for (int i = 0; i < NUM_USERS; i++) {
            double trust = 0.0;
            friend_flag  = false;
            acq_flag     = false;
            fof_flag     = false;

            // ---- Branch 1: direct friend ----
            for (int j = 0; j < size[user][0]; j++) {
                if (friends_array[user][j] == i) {
                    trust = computeop(LL[user][j].getpos(), LL[user][j].getneg(), 1.0);
                    friend_flag = true;
                    break;
                }
            }

            // ---- Branch 2: acquaintance ----
            if (!friend_flag) {
                for (int j = 0; j < asize[user][0]; j++) {
                    if (acq_array[user][j] == i) {
                        trust = computeop(LL[user][j].getpos(), LL[user][j].getneg(), 0.5);
                        acq_flag = true;
                        break;
                    }
                }
            }

            // ---- Branch 3: friend-of-friend (uses cache) ----
            if (!friend_flag && !acq_flag) {
                List<int[]> paths = fofCache[user].get(i);
                if (paths != null && !paths.isEmpty()) {
                    fof_flag = true;
                    ArrayList<Opinion> discounts_consensuses = new ArrayList<>();
                    Opinion temp_trust = new Opinion(0.0, 0.0, 1.0, 1.0);

                    for (int[] path : paths) {
                        int friendSlot  = path[0];   // index in friends_array[user]
                        int friendUid   = path[1];   // the friend's uid
                        int fofSlot     = path[2];   // index in friends_array[friendUid]

                        Opinion op_user_to_friend = getop(
                            LL[user][friendSlot].getpos(),
                            LL[user][friendSlot].getneg(), 1.0);
                        Opinion op_friend_to_fof  = getop(
                            LL[friendUid][fofSlot].getpos(),
                            LL[friendUid][fofSlot].getneg(), 1.0);

                        discounts_consensuses.add(op_user_to_friend.discount(op_friend_to_fof));
                    }

                    for (Opinion dc : discounts_consensuses)
                        temp_trust = temp_trust.consensus(dc);
                    trust = temp_trust.expectedValue();
                }
            }

            // ---- Branch 4: global trust (no path) ----
            if (!friend_flag && !acq_flag && !fof_flag) {
                if (TL[i].state)
                    trust = computet(TL[i].getwp(), TL[i].getwn(), TL[i].getnumu());
                else
                    trust = computet(UL[i].getwp(), UL[i].getwn(), UL[i].getnumu());
            }

            Relation rel1 = this.nw.getUserRelation(user, i);
            rel1.setTrust(trust);
        }
    }

    // ======================== HELPERS ========================

    private boolean isfriend(int uid, int fid) {
        int s = size[uid][0];
        for (int i = 0; i < s; i++) {
            if (friends_array[uid][i] == fid) return true;
        }
        return false;
    }

    private boolean isacqua(int uid, int aquid) {
        int s = asize[uid][0];
        for (int i = 0; i < s; i++) {
            if (acq_array[uid][i] == aquid) return true;
        }
        return false;
    }

    public double computet(double wp, double wn, int nu) {
        double v = variance(wp, wn);
        return (((wp * nu) / (((wp + wn) * (wp + wn)) + 2.0)) * v);
    }

    public double computeop(int p, int n, double a) {
        double b = (p / (p + n + 2.0));
        double d = (n / (p + n + 2.0));
        double u = (2.0 / (p + n + 2.0));
        return (b + (a * u));
    }

    public Opinion getop(int p, int n, double a) {
        double b = (p / (p + n + 2.0));
        double d = (n / (p + n + 2.0));
        double u = (2.0 / (p + n + 2.0));
        return new Opinion(b, d, u, a);
    }

    public double variance(double pos, double neg) {
        if (pos > 0.0 && neg == 0.0) return 1.0;
        if (pos == 0.0 && neg == 0.0) return 0.0;
        double total = pos + neg;
        double p = pos / total;
        double n = neg / total;
        return (p - n);
    }
}