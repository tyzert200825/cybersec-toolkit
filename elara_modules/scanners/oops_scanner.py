#!/usr/bin/env python3
"""
Oops Commits Scanner
====================
Scans GH Archive for "zero-commit" PushEvents — force pushes that deleted commits.
These are commits developers tried to remove, often because they leaked secrets.

Based on Sharon Brizinov's research:
https://trufflesecurity.com/blog/guest-post-how-i-scanned-all-of-github-s-oops-commits-for-leaked-secrets

Key insight: GitHub never actually deletes commits. A zero-commit PushEvent
means the developer force-pushed to remove a commit. The "before" SHA points
to the commit that was the HEAD before deletion — and GitHub still serves it.

Usage:
    python3 oops_scanner.py --hour 2024-01-15-12
    python3 oops_scanner.py --range 3 --max-scans 20
    python3 oops_scanner.py --hour 2024-01-15-12 --dry-run
"""

import argparse
import gzip
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import quote_plus

# Reuse helpers from main pipeline
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gh_secret_hunter import (
    download_archive, generate_hour_keys, USER_AGENT,
    github_api_get, fetch_diff, run_trufflehog, check_rate_limit,
    GITHUB_API_BASE, _RATE_LIMITED
)


def find_oops_commits(archive_path: str) -> list[dict]:
    """
    Find zero-commit PushEvents in a GH Archive file.
    
    A zero-commit PushEvent = force push that removed commits.
    The "before" field = SHA of the commit that was HEAD before deletion.
    The "head" field = SHA of the new HEAD (the commit it was reset to).
    
    We want to fetch the "before" commit — the deleted one.
    """
    oops_commits = []
    
    with open(archive_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            if event.get("type") != "PushEvent":
                continue
            
            payload = event.get("payload", {})
            commits = payload.get("commits", [])
            
            # Zero-commit push = force push that deleted commits
            if len(commits) == 0:
                before_sha = payload.get("before", "")
                head_sha = payload.get("head", "")
                
                # Skip initial pushes (before is all zeros)
                if before_sha and before_sha != "0000000000000000000000000000000000000000":
                    repo = event.get("repo", {}).get("name", "")
                    actor = event.get("actor", {}).get("login", "")
                    created_at = event.get("created_at", "")
                    
                    # Old format: commits array exists but is empty
                    # New format: no commits key at all, check if size/distinct_size exist
                    size = payload.get("size", 0)
                    
                    oops_commits.append({
                        "repo": repo,
                        "deleted_sha": before_sha,  # The commit that was deleted
                        "new_head": head_sha,       # What it was reset to
                        "actor": actor,
                        "date": created_at,
                        "size": size,
                    })
    
    return oops_commits


def scan_oops_commit(repo: str, deleted_sha: str, github_token: str = None) -> dict | None:
    """
    Fetch a deleted commit's diff and scan it with TruffleHog.
    
    Even though the commit was "deleted" via force push, GitHub still serves it
    if you know the full SHA. We fetch the diff and run TruffleHog with verification.
    """
    # Fetch the diff of the deleted commit
    diff = fetch_diff(repo, deleted_sha, github_token)
    if not diff:
        return None
    
    # Run TruffleHog on the diff
    findings = run_trufflehog(diff)
    if findings:
        return {
            "repo": repo,
            "deleted_sha": deleted_sha,
            "diff_size": len(diff),
            "findings": findings,
        }
    
    return None


def run_oops_scanner(
    hours_back: int = 1,
    specific_hour: str = None,
    dry_run: bool = False,
    github_token: str = None,
    max_scans: int = 20,
    json_out: str = None,
) -> list[dict]:
    """Run the oops commits scanner."""
    
    hour_keys = generate_hour_keys(hours_back, specific_hour)
    print(f"\n[*] Oops Commits Scanner")
    print(f"[*] Targeting {len(hour_keys)} hour(s): {', '.join(hour_keys)}")
    
    all_findings = []
    total_oops = 0
    total_scanned = 0
    
    for hour_key in hour_keys:
        print(f"\n{'='*60}")
        print(f"[*] Processing hour: {hour_key}")
        print(f"{'='*60}")
        
        json_path = download_archive(hour_key)
        if not json_path:
            continue
        
        print(f"  [scan] Finding zero-commit PushEvents (force pushes)...")
        oops = find_oops_commits(json_path)
        total_oops += len(oops)
        print(f"  [scan] Found {len(oops)} deleted commits (oops commits)")
        
        if dry_run:
            print(f"  [dry-run] Skipping diff fetch + TruffleHog")
            for o in oops[:20]:
                print(f"    {o['repo']} | deleted: {o['deleted_sha'][:8]} | by: {o['actor']}")
            if len(oops) > 20:
                print(f"    ... and {len(oops) - 20} more")
            continue
        
        # Deduplicate by repo + deleted_sha
        seen = set()
        unique_oops = []
        for o in oops:
            key = f"{o['repo']}@{o['deleted_sha']}"
            if key not in seen:
                seen.add(key)
                unique_oops.append(o)
        
        print(f"  [scan] {len(unique_oops)} unique deleted commits to scan")
        
        # Check rate limit
        rl = check_rate_limit(github_token)
        if rl:
            print(f"  [rate-limit] core: {rl.get('core_remaining', '?')}/{rl.get('core_limit', '?')}")
        
        scan_count = min(len(unique_oops), max_scans)
        print(f"  [scan] Scanning up to {scan_count} deleted commits...")
        
        for i, oops_commit in enumerate(unique_oops[:max_scans]):
            if _RATE_LIMITED:
                print(f"  [rate-limited] Stopping — GitHub API limit reached")
                break
            
            repo = oops_commit["repo"]
            sha = oops_commit["deleted_sha"]
            print(f"  [{i+1}/{scan_count}] {repo} | deleted: {sha[:8]} | by: {oops_commit['actor']}")
            
            result = scan_oops_commit(repo, sha, github_token)
            total_scanned += 1
            
            if result:
                for f in result["findings"]:
                    f["repo"] = repo
                    f["deleted_sha"] = sha
                    f["actor"] = oops_commit["actor"]
                    f["hour"] = hour_key
                    f["commit_type"] = "deleted_force_push"
                    all_findings.append(f)
                    verified_str = "VERIFIED" if f.get("verified") else "unverified"
                    print(f"    [{verified_str}] {f['detector']}")
            
            time.sleep(0.5)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"[*] OOPS SCANNER SUMMARY")
    print(f"{'='*60}")
    print(f"  Hours processed:      {len(hour_keys)}")
    print(f"  Total oops commits:    {total_oops}")
    print(f"  Scanned:              {total_scanned}")
    print(f"  Secrets found:        {len(all_findings)}")
    verified_count = sum(1 for f in all_findings if f.get("verified"))
    print(f"  Verified secrets:     {verified_count}")
    
    if json_out and all_findings:
        safe_findings = [{k: v for k, v in f.items() if k != "raw_secret"} for f in all_findings]
        with open(json_out, 'w') as f:
            json.dump(safe_findings, f, indent=2)
        print(f"  Results saved to:     {json_out}")
    
    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub 'oops commits' (force-pushed/deleted commits) for leaked secrets"
    )
    parser.add_argument("--hour", type=str, default=None,
                        help="Specific hour (format: YYYY-MM-DD-H)")
    parser.add_argument("--range", type=int, default=1,
                        help="Number of hours to process")
    parser.add_argument("--dry-run", action="store_true",
                        help="Find oops commits without scanning")
    parser.add_argument("--max-scans", type=int, default=20,
                        help="Max deleted commits to scan per run")
    parser.add_argument("--json-out", type=str, default=None,
                        help="Save findings to JSON file")
    parser.add_argument("--github-token", type=str, default=None,
                        help="GitHub API token")
    
    args = parser.parse_args()
    github_token = args.github_token or os.environ.get("GITHUB_TOKEN")
    
    findings = run_oops_scanner(
        hours_back=args.range,
        specific_hour=args.hour,
        dry_run=args.dry_run,
        github_token=github_token,
        max_scans=args.max_scans,
        json_out=args.json_out,
    )
    
    if findings:
        print(f"\n[*] Found {len(findings)} secrets in deleted commits!")
        verified = [f for f in findings if f.get("verified")]
        if verified:
            print(f"[*] {len(verified)} VERIFIED:")
            for f in verified:
                print(f"  - {f['detector']} in {f['repo']} (deleted commit {f['deleted_sha'][:8]})")


if __name__ == "__main__":
    main()
