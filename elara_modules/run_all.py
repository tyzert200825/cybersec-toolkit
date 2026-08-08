#!/usr/bin/env python3
"""
Elara SecOps — Master Pipeline Runner
=====================================
Orchestrates all secret hunting scanners in sequence or parallel.
Outputs unified findings to output/findings/ and optionally uploads to Base44.

Usage:
    python3 run_all.py                        # Run everything
    python3 run_all.py --scanners gh,dork,paste  # Run specific scanners
    python3 run_all.py --range 6              # Last 6 hours
    python3 run_all.py --export csv           # Export to CSV
    python3 run_all.py --upload               # Upload to Base44 entity
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNERS = {
    "gh":       ("GitHub Archive Hunter", f"{SCRIPT_DIR}/scanners/gh_secret_hunter.py"),
    "dork":     ("Google Dorker",          f"{SCRIPT_DIR}/scanners/google_dorker.py"),
    "paste":    ("Paste Site Monitor",     f"{SCRIPT_DIR}/scanners/paste_monitor.py"),
    "code":     ("Code Dorker",            f"{SCRIPT_DIR}/scanners/code_dorker.py"),
    "oops":     ("Oops Commits Scanner",   f"{SCRIPT_DIR}/scanners/oops_scanner.py"),
    "pandas":   ("Pandas Scanner",        f"{SCRIPT_DIR}/scanners/pandas_scanner.py"),
}

OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output", "findings")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_scanner(name, script_path, extra_args=None):
    """Run a single scanner and return its findings."""
    label = SCANNERS[name][0]
    print(f"\n{'='*60}")
    print(f"  Running: {label}")
    print(f"{'='*60}")

    cmd = [sys.executable, script_path]
    if extra_args:
        cmd.extend(extra_args)

    # Add JSON output
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(OUTPUT_DIR, f"{name}_{timestamp}.json")
    cmd.extend(["--json-out", outfile] if "--json-out" not in str(extra_args) else [])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)
        if result.stderr:
            print(f"  [stderr] {result.stderr[-500:]}")

        # Load findings
        findings = []
        if os.path.exists(outfile):
            with open(outfile, "r") as f:
                data = json.load(f)
                findings = data if isinstance(data, list) else data.get("findings", [])
        
        print(f"  [{name}] Found {len(findings)} findings → {outfile}")
        return findings
    except subprocess.TimeoutExpired:
        print(f"  [{name}] TIMEOUT after 600s")
        return []
    except Exception as e:
        print(f"  [{name}] ERROR: {e}")
        return []

def export_csv(all_findings, path):
    """Export findings to CSV."""
    import csv
    if not all_findings:
        print("No findings to export.")
        return
    fields = ["date","severity","secretType","secretValue","repo","file","url",
              "method","disclosure","bountyProgram","bountyMin","bountyMax",
              "dorkQuery","scanMethod","verified","scanTime"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for finding in all_findings:
            w.writerow(finding)
    print(f"Exported {len(all_findings)} findings to {path}")

def main():
    parser = argparse.ArgumentParser(description="Elara SecOps Master Pipeline Runner")
    parser.add_argument("--scanners", type=str, default="all",
                        help="Comma-separated scanner names: gh,dork,paste,code,oops,pandas")
    parser.add_argument("--range", type=int, default=6,
                        help="Hours to scan back (default: 6)")
    parser.add_argument("--export", type=str, choices=["csv","json","both"], default="json",
                        help="Export format")
    parser.add_argument("--upload", action="store_true",
                        help="Upload findings to Base44 SecretFinding entity")
    args = parser.parse_args()

    print(f"\n{'#'*60}")
    print(f"  Elara SecOps — Secret Hunter Pipeline")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print(f"{'#'*60}")

    # Select scanners
    if args.scanners == "all":
        selected = list(SCANNERS.keys())
    else:
        selected = [s.strip() for s in args.scanners.split(",") if s.strip() in SCANNERS]

    if not selected:
        print("No valid scanners selected!")
        print(f"Available: {', '.join(SCANNERS.keys())}")
        sys.exit(1)

    print(f"\nScanners: {', '.join(selected)}")
    print(f"Range: {args.range} hours")

    all_findings = []
    start_time = time.time()

    for name in selected:
        label, script = SCANNERS[name]
        extra = []
        if name in ("gh", "oops"):
            extra = ["--range", str(args.range)]
        if name == "dork":
            extra = ["--github"]
        if name == "code":
            extra = ["--dorks", "all"]
        
        findings = run_scanner(name, script, extra)
        all_findings.extend(findings)

    elapsed = time.time() - start_time

    # Deduplicate by secret value
    seen = set()
    unique = []
    for f in all_findings:
        key = f.get("secretValue", "") + f.get("url", "")
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Save combined results
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    combined_path = os.path.join(OUTPUT_DIR, f"combined_{timestamp}.json")
    with open(combined_path, "w") as f:
        json.dump(unique, f, indent=2)

    # Export
    if args.export in ("csv", "both"):
        csv_path = os.path.join(OUTPUT_DIR, f"combined_{timestamp}.csv")
        export_csv(unique, csv_path)

    # Summary
    print(f"\n{'='*60}")
    print(f"  PIPELINE COMPLETE")
    print(f"{'='*60}")
    print(f"  Total findings:    {len(all_findings)}")
    print(f"  Unique findings:   {len(unique)}")
    print(f"  Time elapsed:       {elapsed:.1f}s")
    print(f"  Output:            {combined_path}")

    by_sev = {}
    for f in unique:
        sev = f.get("severity", "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    if by_sev:
        print(f"  By severity:       {json.dumps(by_sev)}")

    # Upload to Base44 if requested
    if args.upload and unique:
        print(f"\n  Uploading {len(unique)} findings to Base44...")
        try:
            upload_script = os.path.join(SCRIPT_DIR, "upload_findings.py")
            if os.path.exists(upload_script):
                subprocess.run([sys.executable, upload_script, combined_path], check=True)
            else:
                print("  upload_findings.py not found. Skipping upload.")
        except Exception as e:
            print(f"  Upload error: {e}")

    print(f"\n{'='*60}\n")

if __name__ == "__main__":
    main()
