#!/usr/bin/env python3
"""
Pandas-Powered GitHub Secret Scanner
=====================================
Uses pandas DataFrames for:
- Bulk pattern loading & management
- GitHub Code Search result processing
- Findings deduplication, filtering, and analysis
- CSV/JSON/Excel export
- Severity scoring & bounty prioritization

Usage:
    python3 pandas_scanner.py --dorks all
    python3 pandas_scanner.py --dorks google,microsoft
    python3 pandas_scanner.py --dorks all --export csv
    python3 pandas_scanner.py --dorks all --commit-search
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import quote_plus

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret_patterns import PATTERNS, GITHUB_DORKS

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
TOKEN = os.environ.get("GITHUB_TOKEN", "")
HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": UA,
    "Authorization": f"token {TOKEN}" if TOKEN else "",
}

# BIP39 wordlist for seed phrase false positive filtering
BIP39 = set("""abandon ability able about above absent absorb abstract absurd abuse access
accident account accuse achieve acid acoustic acquire across act action actor actress
actual adapt add addict address adjust admit adult advance advice aerobic affair
afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol
alert alien all alley allow almost alone alpha already also alter always amateur
amazing among amount amused analyst anchor ancient anger angle angry animal ankle
another answer antenna antique anxiety any apart apology appear apple approve
april arch arctic area arena army around arrange arrival arrive arrow art artefact
artwork asset ask assault athlete atom attack attend attitude auction august aunt
author auto autumn average avocado avoid awake aware away awesome awful awkward
axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar
barely bargain barrel base basic basket battle beach bean beauty because become
beef before begin behave behind believe below belt bench benefit best betray
better between beyond bicycle bid bike bind biology bird birth bitter black
blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush
board boat body boil bomb bone bonus book boost border boring borrow boss bottom
bounce box boy bracket brain brand brass brave bread breeze brick bridge brief
bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy
budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus
business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm
camera camp can canal cancel candy cannon canoe canvas canyon capable capital
captain car carbon card cargo carpet carry cart case cash casino castle casual
cat catalog catch category cattle caught cause caution cave ceiling celery
cement census century cereal certain chair chalk champion change chaos chapter
charge chase chat cheap check cheese chef cherry chest chicken chief child
chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen
city civil claim clap clarify claw clay clean clerk clever click client cliff
climb clinic clip clock clog close cloth cloud clown club clump cluster clutch
coach coast coconut code coffee coil coin collect color column combine come
comfort comic common company concert conduct confirm congress connect consider
control convince cook cool copper copy coral core corn correct cost cotton
couch country couple course cousin cover coyote crack cradle craft cram crane
crash crater crawl crazy cream credit creek crew cricket crime crisp critic
crop cross crowd crown crucial cruel cruise crumble crunch crush cry crystal
cube culture cup cupboard curious current curtain curve cushion custom
cycle""".split())

# Severity scoring for bounty prioritization
SEVERITY_SCORE = {"critical": 100, "high": 60, "medium": 30, "low": 10}

# Bounties by category
BOUNTY_ESTIMATES = {
    "google_accounts": {"min": 500, "max": 31000, "program": "Google VRP"},
    "microsoft_accounts": {"min": 500, "max": 30000, "program": "Microsoft MSRC"},
    "crypto_exchange": {"min": 100, "max": 25000, "program": "Exchange Security"},
    "social_media": {"min": 100, "max": 10000, "program": "Platform Security"},
    "payment": {"min": 500, "max": 25000, "program": "HackerOne"},
    "server_infrastructure": {"min": 100, "max": 15000, "program": "Cloud Provider"},
    "database": {"min": 100, "max": 10000, "program": "Notify Owner"},
    "ai_services": {"min": 100, "max": 5000, "program": "AI Provider Security"},
    "crypto_wallet": {"min": 1000, "max": 100000, "program": "Notify Owner"},
    "telco_australian": {"min": 100, "max": 5000, "program": "ACMA"},
}

PLACEHOLDERS = [
    "example", "your_", "xxx", "placeholder", "test_", "dummy", "sample", "lorem",
    "ipsum", "change_me", "your-key", "yourkey", "secret_key", "your-secret",
    "my-api-key", "replace", "insert", "00000", "aaaa", "NEXT_AUTH_SECRET",
    "YOUR_", "PASTE_", "REPLACE_", "your_api", "your_token", "your_secret",
    "<your", "your-", "put_", "type_your", "add_your", "xxxxx", "XXXXX",
    "REDACTED", "redacted", "xxxxxxxx", "template", "demo_", "fake_",
    "devstoreaccount1", "STUFF HEREX", "1234567890",
]


def is_real_seed(text):
    """Check if 12-word phrase is actually BIP39."""
    words = text.lower().strip().split()
    if len(words) < 12:
        return False
    return sum(1 for w in words[:12] if w in BIP39) >= 11


def load_patterns_df():
    """Load all regex patterns into a pandas DataFrame for bulk processing."""
    rows = []
    for category, patterns in PATTERNS.items():
        for pat in patterns:
            rows.append({
                "category": category,
                "name": pat["name"],
                "regex": pat["regex"],
                "severity": pat["severity"],
                "method": pat.get("method", ""),
                "disclosure": pat.get("disclosure", ""),
                "compiled": re.compile(pat["regex"], re.IGNORECASE),
            })
    df = pd.DataFrame(rows)
    df["severity_score"] = df["severity"].map(SEVERITY_SCORE).fillna(0)
    return df


def scan_content(content, patterns_df):
    """Scan content using pandas DataFrame of patterns — vectorized approach."""
    findings = []
    for _, row in patterns_df.iterrows():
        for m in row["compiled"].finditer(content):
            val = m.group(1) if m.groups() else m.group(0)

            # Filter seed phrase false positives
            if "Seed Phrase" in row["name"] and not is_real_seed(val):
                continue

            # Filter placeholders
            val_lower = val.lower()
            if any(p.lower() in val_lower for p in PLACEHOLDERS):
                continue
            if len(val) < 10:
                continue

            s = max(0, m.start() - 120)
            e = min(len(content), m.end() + 120)
            ctx = content[s:e].replace("\n", " ").strip()

            findings.append({
                "category": row["category"],
                "secret_type": row["name"],
                "secret_value": val,
                "context": ctx[:300],
                "severity": row["severity"],
                "severity_score": row["severity_score"],
                "method": row["method"][:300],
                "disclosure": row["disclosure"],
                "bounty_min": BOUNTY_ESTIMATES.get(row["category"], {}).get("min", 0),
                "bounty_max": BOUNTY_ESTIMATES.get(row["category"], {}).get("max", 0),
                "bounty_program": BOUNTY_ESTIMATES.get(row["category"], {}).get("program", ""),
            })
    return findings


def gh_code_search(query, per_page=10):
    """GitHub Code Search API."""
    url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page={per_page}"
    try:
        req = Request(url, headers=HEADERS)
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")).get("items", [])
    except HTTPError as e:
        if e.code == 403:
            return None  # Rate limited
        return []
    except:
        return []


def fetch_raw(repo, path):
    """Fetch raw file content from GitHub."""
    for b in ["main", "master"]:
        url = f"https://raw.githubusercontent.com/{repo}/{b}/{path}"
        try:
            req = Request(url, headers={"User-Agent": UA})
            with urlopen(req, timeout=8) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except:
            pass
    return None


def fetch_patch(repo, sha):
    """Fetch commit .patch content (bypasses API rate limits)."""
    url = f"https://github.com/{repo}/commit/{sha}.patch"
    try:
        req = Request(url, headers={"User-Agent": UA})
        with urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except:
        return None


def search_commits(query, per_page=10):
    """GitHub Commit Search API."""
    url = f"https://api.github.com/search/commits?q={quote_plus(query)}&per_page={per_page}&sort=committer-date&order=desc"
    try:
        req = Request(url, headers=HEADERS)
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")).get("items", [])
    except:
        return []


def run_scan(dork_filter=None, do_commit_search=False, max_dorks=None):
    """Main scanning function using pandas for data processing."""
    ts = datetime.now(timezone.utc).isoformat()

    # Load patterns into DataFrame
    patterns_df = load_patterns_df()
    print(f"\n{'='*60}")
    print(f"  PANDAS GITHUB SCANNER")
    print(f"  {ts}")
    print(f"  Patterns: {len(patterns_df)} | Categories: {patterns_df['category'].nunique()}")
    print(f"  Token: {'✅ Active' if TOKEN else '❌ None'}")
    print(f"{'='*60}\n")

    # Select dorks
    dorks = GITHUB_DORKS
    if dork_filter and dork_filter != "all":
        cats = [c.strip() for c in dork_filter.split(",")]
        dorks = [d for d in GITHUB_DORKS if any(c.lower() in d.lower() for c in cats)]
    if max_dorks:
        dorks = dorks[:max_dorks]

    all_raw_findings = []
    scanned = 0
    rate_hits = 0

    # === PHASE 1: Code Search ===
    print(f"--- CODE SEARCH: {len(dorks)} dorks ---\n")

    for i, dork in enumerate(dorks):
        if rate_hits > 3:
            print(f"[!] Rate limited, waiting 60s...")
            time.sleep(60)
            rate_hits = 0

        print(f"[{i+1}/{len(dorks)}] {dork[:55]}")
        results = gh_code_search(dork, per_page=5)

        if results is None:
            print(f"  ⚠️  Rate limited")
            rate_hits += 1
            time.sleep(30)
            continue

        if not results:
            print(f"  No results")
            time.sleep(7)
            continue

        print(f"  {len(results)} files")

        for item in results[:5]:
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            html_url = item.get("html_url", "")

            content = fetch_raw(repo, path)
            if not content or len(content) < 10:
                continue

            scanned += 1
            found = scan_content(content, patterns_df)
            for f in found:
                f["repo"] = repo
                f["file"] = path
                f["url"] = html_url
                f["scan_method"] = "code_search"
                f["dork_query"] = dork
                all_raw_findings.append(f)

            if found:
                for f in found:
                    print(f"  [!!!] {f['severity'].upper()} — {f['secret_type']}: {f['secret_value'][:50]}")

        # Code search: 10 req/min
        time.sleep(7)

        # Extra wait every 10 queries
        if (i + 1) % 10 == 0 and i < len(dorks) - 1:
            print(f"\n[*] Batch pause 60s...\n")
            time.sleep(62)

    # === PHASE 2: Commit Search ===
    if do_commit_search:
        print(f"\n--- COMMIT SEARCH ---\n")
        commit_queries = [
            "remove GOOGLE_CLIENT_SECRET", "remove AZURE_CLIENT_SECRET",
            "remove COINBASE_ACCESS_TOKEN", "remove COINSPOT_API_KEY",
            "remove SNAPCHAT_CLIENT_SECRET", "remove FIREBASE_API_KEY",
            "remove GOCSPX", "remove GOOGLE_API_KEY",
            "remove secrets .env committed", "rotate api keys env",
            "remove binance secret key", "remove coinbase api secret",
            "remove snapchat api token", "revert env file secrets",
        ]

        for q in commit_queries:
            print(f"[*] {q}")
            commits = search_commits(q, per_page=5)
            if not commits:
                print(f"  No results")
                time.sleep(3)
                continue

            print(f"  {len(commits)} commits")
            for c in commits[:5]:
                repo = c.get("repo", {}).get("full_name", "")
                sha = c.get("sha", "")
                msg = c.get("commit", {}).get("message", "")[:60]
                date = c.get("commit", {}).get("committer", {}).get("date", "")[:10]

                content = fetch_patch(repo, sha)
                if not content:
                    continue

                scanned += 1
                found = scan_content(content, patterns_df)
                for f in found:
                    f["repo"] = repo
                    f["sha"] = sha
                    f["date"] = date
                    f["commit_msg"] = msg
                    f["url"] = f"https://github.com/{repo}/commit/{sha}"
                    f["scan_method"] = "commit_search"
                    f["dork_query"] = q
                    all_raw_findings.append(f)
                    print(f"  [!!!] {f['severity'].upper()} — {f['secret_type']} in {repo}")
                time.sleep(0.5)
            time.sleep(3)

    # === PROCESS WITH PANDAS ===
    print(f"\n{'='*60}")
    print(f"  PANDAS ANALYSIS")
    print(f"{'='*60}\n")

    if not all_raw_findings:
        print("No findings to analyze.")
        return pd.DataFrame()

    df = pd.DataFrame(all_raw_findings)

    # Deduplicate by secret_value + repo
    df = df.drop_duplicates(subset=["secret_value", "repo"], keep="first")

    # Add timestamp
    df["scan_timestamp"] = ts

    # Sort by severity score descending
    df = df.sort_values("severity_score", ascending=False).reset_index(drop=True)

    # === SUMMARY STATS ===
    print(f"Total unique findings: {len(df)}")
    print(f"Files scanned: {scanned}")
    print(f"\nBy severity:")
    print(df["severity"].value_counts().to_string())
    print(f"\nBy category:")
    print(df["category"].value_counts().to_string())
    print(f"\nBy scan method:")
    print(df["scan_method"].value_counts().to_string())

    # Top bounty potential
    print(f"\nTop bounty potential:")
    top = df.nlargest(10, "severity_score")[
        ["secret_type", "repo", "severity", "bounty_min", "bounty_max", "bounty_program"]
    ]
    print(top.to_string(index=False))

    # === DETAILED FINDINGS ===
    print(f"\n{'='*60}")
    print(f"  DETAILED FINDINGS")
    print(f"{'='*60}")

    for i, row in df.iterrows():
        print(f"\n--- FINDING {i+1} [{row['severity'].upper()}] ---")
        print(f"  Type: {row['secret_type']}")
        print(f"  Category: {row['category']}")
        print(f"  Repo: {row['repo']}")
        print(f"  File: {row.get('file', row.get('sha', '?'))}")
        print(f"  URL: {row['url']}")
        print(f"  Secret: {row['secret_value'][:120]}")
        print(f"  Context: {row['context'][:200]}")
        print(f"  Method: {row['method'][:200]}")
        print(f"  Disclosure: {row['disclosure']}")
        print(f"  Bounty: {row['bounty_program']} (${row['bounty_min']:,}–${row['bounty_max']:,})")

    # === EXPORT ===
    export_cols = [
        "category", "secret_type", "secret_value", "severity", "severity_score",
        "repo", "file", "url", "context", "method", "disclosure",
        "bounty_min", "bounty_max", "bounty_program", "scan_method", "dork_query",
        "scan_timestamp",
    ]
    export_df = df[export_cols].copy()

    # Always save JSON
    export_df.to_json("pandas_scan_results.json", orient="records", indent=2)
    print(f"\n✅ Saved to pandas_scan_results.json")

    # Also save CSV
    export_df.to_csv("pandas_scan_results.csv", index=False)
    print(f"✅ Saved to pandas_scan_results.csv")

    # Print CSV summary
    print(f"\n{'='*60}")
    print(f"  CSV SUMMARY")
    print(f"{'='*60}")
    print(export_df[["secret_type", "severity", "repo", "bounty_program"]].to_string(index=False))

    return export_df


def main():
    parser = argparse.ArgumentParser(description="Pandas-Powered GitHub Secret Scanner")
    parser.add_argument("--dorks", type=str, default="all", help="Dork filter (all, google, microsoft, coinbase, etc.)")
    parser.add_argument("--commit-search", action="store_true", help="Also search commit messages")
    parser.add_argument("--max-dorks", type=int, default=None, help="Max dorks to process")
    parser.add_argument("--export", type=str, default="csv,json", help="Export format")
    args = parser.parse_args()

    df = run_scan(
        dork_filter=args.dorks,
        do_commit_search=args.commit_search,
        max_dorks=args.max_dorks,
    )

    if df is not None and len(df) > 0:
        print(f"\n\nDONE: {len(df)} findings saved.")
    else:
        print(f"\n\nDONE: No findings.")


if __name__ == "__main__":
    main()
