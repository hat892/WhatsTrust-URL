@echo off
echo ========================================
echo  Running All Experiments
echo ========================================
echo.

REM ── STEP 0: Pre-classify all URLs (run once) ──────────────
REM This generates url_cache.txt with label + P(phishing) for
REM every URL. Only needed when the model changes.
REM Uncomment the line below to regenerate:
REM python prepare_url_cache.py

echo ── Standard baseline runs ────────────────────────────────
echo.

echo [1/4] EigenTrust - Naive Strategy...
for %%f in (*.trace) do (
    echo   %%f
    java -cp "." TraceSimulator -input %%f -tm eigen -strategy naive
)

echo.
echo [2/4] WhatsTrust+URL - Naive Strategy (K=1 default)...
for %%f in (*.trace) do (
    echo   %%f
    java -cp "." TraceSimulator -input %%f -tm whatstrust -strategy naive
)

echo.
echo ── Penalty K ablation (Issue 3) ──────────────────────────
echo  Runs K=1,2,5,10 to find the best trade-off between
echo  phishing delivery rate and false-positive trust cost.
echo.

echo [3/4] K ablation sweep...
for %%f in (*.trace) do (
    for %%k in (1 2 5 10) do (
        echo   K=%%k on %%f
        java -cp "." -DpenaltyK=%%k ^
            TraceSimulator -input %%f -tm whatstrust -strategy naive
    )
)

echo.
echo ── Sensitivity analysis (Issue 5c) ───────────────────────
echo  7 seeds x 3 assumption combos to justify assumptions
echo  and produce mean +/- std-dev (Issue 5a).
echo.

echo [4/4] Sensitivity analysis...
for %%f in (*.trace) do (
    for %%p in (0.05 0.10 0.20) do (
        for %%l in (0.10 0.20 0.30) do (
            for %%s in (1001 1002 1003 1004 1005 1006 1007) do (
                java -cp "." -DfwdPhiProb=%%p -DlegitURLProb=%%l ^
                    TraceSimulator -input %%f -tm whatstrust -strategy naive -seed %%s
            )
        )
    )
)

echo.
echo ========================================
echo  All experiments complete!
echo.
echo  Output files:
echo    resultsCSV.csv       - success rate (all runs)
echo    metrics_results.csv  - M1/M2/M3 + K + seed (all runs)
echo.
echo  Next:
echo    python parse_results.py    - success rate charts
echo    python parse_metrics.py    - M1/M2/M3 mean+/-stddev table
echo    python plot_k_ablation.py  - K trade-off curve for paper
echo ========================================
pause