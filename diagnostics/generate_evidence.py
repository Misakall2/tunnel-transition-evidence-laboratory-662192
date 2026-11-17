"""Offline evidence generator.

Run from the repository root with:  python diagnostics/generate_evidence.py

It performs no network access: every byte comes from in-memory transcripts.
Writes diagnostics/evidence/evidence.json plus a small human-readable summary.
"""

import json
import os
import sys

# Make the repo root importable when invoked directly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tunnellab.replay import redaction_evidence, run_all  # noqa: E402
from tunnellab.scenarios import FRAGMENTATIONS  # noqa: E402


def main() -> int:
    results, rejections, evidence = run_all()
    redaction = redaction_evidence()

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "evidence.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "schema_version": 1,
                "network_access": "none - fully in-memory replay",
                "runs": evidence,
                "policy_rejections": [
                    {
                        "scenario": r.scenario,
                        "passed": r.passed,
                        "assertions": r.assertions,
                        "failures": r.assertion_failures,
                    }
                    for r in rejections
                ],
                "redaction": redaction,
            },
            fh,
            indent=2,
            sort_keys=True,
        )

    total = len(results)
    failed = [r for r in results if not r.passed]
    print(f"scenario runs: {total} ({len(FRAGMENTATIONS)} fragmentation strategies each)")
    print(f"policy rejection checks: {len(rejections)}")
    print(f"redaction leak check: {'PASS' if redaction['secret_values_absent_from_trace'] else 'FAIL'}")
    if failed:
        print(f"FAILURES: {len(failed)}")
        for r in failed:
            print(f"  - {r.scenario} [{r.fragmentation}]")
            for msg in r.assertion_failures:
                print(f"      {msg}")
        return 1
    print("all assertions passed")
    print(f"evidence written: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
