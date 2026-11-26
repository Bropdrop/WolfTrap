# Historical WT-002 before the prototype was supplied

These original patch and outcome bytes come from the retained preliminary 49-case packet. It accepted one signature per role and a longer claim lifetime. Its results do not qualify the corrected hybrid policy. The corrected WT-002 candidate requires both algorithms for each role and a maximum 30-second lifetime. Both snapshots preserve their own tests and limitations.

In a separate disposable checkout of main commit 7962c3a77b3e94145ec99063c142d860e6389bb2, apply this historical patch and run challenge.py and mutants.py from experiments/cryptofall. Compare their standard output byte for byte with the two included JSONL files. Use the recorded WT-002 laboratory runtime.
