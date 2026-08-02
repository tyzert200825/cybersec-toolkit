#!/usr/bin/env python3
"""
GitHub Code Search Dorker
========================
Uses GitHub's Code Search API to search for specific secret patterns in file
contents across all public repositories. Unlike commit-message-based filtering,
this searches the actual code content.

Based on the Lasso Security methodology and win3zz's GitHub dorking gist:
https://gist.github.com/win3zz/0a1c70589fcbea64dba4588b93095855

Key insight: GitHub Code Search can find secrets by their known prefixes and
patterns (e.g., "sk-" for OpenAI, "ghp_" for GitHub PATs, "AKIA" for AWS keys).

Usage:
    python3 code_dorker.py --dry-run
    python3 code_dorker.py --max-results 100 --json-out dorks.json
    python3 code_dorker.py --target openai
"""

import argparse
import json
import os
import sys
import time
from urllib.parse import quote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gh_secret_hunter import (
    USER_AGENT, GITHUB_API_BASE, github_api_get,
    fetch_diff, run_trufflehog, check_rate_limit, _RATE_LIMITED
)


# ─── Secret-specific dork queries ─────────────────────────────────────────────
# Each query targets a specific secret type with known prefixes/patterns.
# Format: (name, search_query, file_extensions)

DORK_QUERIES = [
    # AI / ML API keys
    ("OpenAI API Key", 'sk- AND (openai OR gpt OR chatgpt) extension:env', None),
    ("Anthropic API Key", 'sk-ant- AND (anthropic OR claude) extension:env', None),
    ("HuggingFace Token", 'hf_ AND (huggingface OR hugging OR hf_token) extension:env', None),
    ("WandB Token", 'wandb_api_key AND (wandb OR weights) extension:py', None),

    # Cloud provider keys
    ("AWS Access Key", 'AKIA AND (aws OR amazon) extension:env', None),
    ("AWS Secret Key", 'aws_secret_access_key AND (secret OR key) extension:env', None),
    ("GCP Service Key", 'type AND service_account AND private_key extension:json', None),
    ("Azure Key", 'azure_storage_account_key AND (azure OR storage) extension:env', None),

    # GitHub tokens
    ("GitHub PAT", 'ghp_ AND (github OR token OR pat) extension:env', None),
    ("GitHub OAuth", 'gho_ AND (github OR oauth) extension:env', None),
    ("GitHub App", 'ghs_ AND (github OR app) extension:env', None),
    ("GitHub Refresh", 'ghr_ AND (github OR refresh) extension:env', None),

    # Payment / Finance
    ("Stripe Secret", 'sk_live_ AND (stripe OR payment) extension:env', None),
    ("Stripe Test", 'sk_test_ AND (stripe OR payment) extension:env', None),
    ("RazorPay Live", 'rzp_live_ extension:env', None),
    ("PayPal Client", 'client_secret AND (paypal OR paypal_client) extension:env', None),

    # Communication
    ("Slack Bot Token", 'xoxb- AND (slack OR bot) extension:env', None),
    ("Slack User Token", 'xoxp- AND (slack OR user) extension:env', None),
    ("Discord Bot", 'discord_token AND (discord OR bot) extension:env', None),
    ("Twilio Token", 'twilio_auth_token AND (twilio OR sms) extension:env', None),
    ("SendGrid Key", 'SG. AND (sendgrid OR email) extension:env', None),
    ("Mailgun Key", 'key- AND (mailgun OR mail) extension:env', None),

    # CI/CD
    ("CircleCI Token", 'circle_token AND (circleci OR ci) extension:env', None),
    ("Travis CI Token", 'travis_token AND (travis OR ci) extension:yml', None),
    ("Jenkins Token", 'jenkins_token AND (jenkins OR ci) extension:env', None),

    # Database
    ("MongoDB URI", 'mongodb:// AND (mongodb OR atlas) extension:env', None),
    ("Postgres URI", 'postgresql:// AND (postgres OR pg) extension:env', None),
    ("Redis URL", 'redis:// AND (redis OR cache) extension:env', None),

    # Monitoring / Logging
    ("Datadog Key", 'datadog_api_key AND (datadog OR monitoring) extension:env', None),
    ("Sentry DSN", 'sentry_dsn AND (sentry OR error) extension:env', None),
    ("NewRelic Key", 'newrelic_license_key AND (newrelic OR apm) extension:env', None),

    # Config files with secrets
    (".env with secrets", 'SECRET_KEY AND (django OR flask OR secret) extension:env', None),
    (".env production", 'env_file AND (production OR prod) extension:env', None),
    ("Firebase Config", 'firebase_admin_sdk AND (firebase OR google) extension:json', None),

    # MCP configs (new attack surface from GitGuardian 2026 report)
    ("MCP Config Secrets", 'mcp AND (api_key OR token OR secret) extension:json', None),
    ("MCP Config Env", 'mcp AND (api_key OR token OR secret) extension:json', None),
]

# Target groups for focused scanning
TARGET_GROUPS = {
    "ai": ["OpenAI API Key", "Anthropic API Key", "HuggingFace Token", "WandB Token", "MCP Config Secrets", "MCP Config Env"],
    "cloud": ["AWS Access Key", "AWS Secret Key", "GCP Service Key", "Azure Key", "Firebase Config"],
    "github": ["GitHub PAT", "GitHub OAuth", "GitHub App", "GitHub Refresh"],
    "payment": ["Stripe Secret", "Stripe Test", "RazorPay Live", "PayPal Client"],
    "communication": ["Slack Bot Token", "Slack User Token", "Discord Bot", "Twilio Token", "SendGrid Key", "Mailgun Key"],
    "database": ["MongoDB URI", "Postgres URI", "Redis URL"],
    "monitoring": ["Datadog Key", "Sentry DSN", "NewRelic Key"],
    "cicd": ["CircleCI Token", "Travis CI Token", "Jenkins Token"],
    "all": None,  # None = all queries
}


def search_code(query: str, github_token: str = None, max_pages: int = 3) -> list[dict]:
    """Search GitHub code for a specific query. Returns list of code results."""
    results = []
    
    for page in range(1, max_pages + 1):
        if _RATE_LIMITED:
            break
            
        encoded = quote_plus(query)
        url = (
            f"{GITHUB_API_BASE}/search/code"
            f"?q={encoded}&per_page=50&page={page}"
        )
        
        result = github_api_get(url, github_token)
        if not result or not isinstance(result, dict):
            break
        
        items = result.get("items", [])
        if not items:
            break
        
        for item in items:
            results.append({
                "repo": item.get("repository", {}).get("full_name", ""),
                "path": item.get("path", ""),
                "url": item.get("html_url", ""),
                "sha": item.get("sha", ""),
                "score": item.get("score", 0),
            })
        
        total_count = result.get("total_count", 0)
        if page * 50 >= total_count:
            break
        
        # Code search rate limit: 10 req/min without token, 30/min with token
        time.sleep(6 if not github_token else 2)
    
    return results


def fetch_file_content(repo: str, path: str, github_token: str = None) -> str | None:
    """Fetch raw file content from GitHub."""
    url = f"https://raw.githubusercontent.com/{repo}/HEAD/{path}"
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT})
        if github_token:
            req.add_header("Authorization", f"Bearer {github_token}")
        with urlopen(req) as resp:
            return resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        print(f"    [error] fetching {repo}/{path}: {e}")
        return None


def scan_file_with_trufflehog(content: str, filename: str = "secret.txt") -> list[dict]:
    """Write content to a temp file and scan with TruffleHog."""
    work_dir = tempfile.mkdtemp(prefix="dorker_")
    file_path = os.path.join(work_dir, filename)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    cmd = [
        "trufflehog", "filesystem",
        work_dir,
        "--json",
        "--no-update",
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception:
        return []
    
    findings = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        try:
            finding = json.loads(line)
            findings.append({
                "detector": finding.get("DetectorName", "unknown"),
                "verified": finding.get("Verified", False),
                "raw_secret": finding.get("Raw", ""),
                "source": finding.get("SourceMetadata", {}),
            })
        except json.JSONDecodeError:
            continue
    
    return findings


import subprocess
import tempfile


def run_code_dorker(
    target: str = "all",
    dry_run: bool = False,
    max_results: int = 50,
    max_scan: int = 20,
    github_token: str = None,
    json_out: str = None,
) -> list[dict]:
    """Run the GitHub code search dorker."""
    
    # Determine which queries to run
    target_queries = TARGET_GROUPS.get(target, None)
    if target_queries:
        queries = [(name, q, ext) for name, q, ext in DORK_QUERIES if name in target_queries]
    else:
        queries = DORK_QUERIES
    
    print(f"\n[*] GitHub Code Search Dorker")
    print(f"[*] Target: {target} ({len(queries)} query patterns)")
    
    rl = check_rate_limit(github_token)
    if rl:
        print(f"  [rate-limit] core: {rl.get('core_remaining', '?')}/{rl.get('core_limit', '?')}, "
              f"search: {rl.get('search_remaining', '?')}/{rl.get('search_limit', '?')}")
    
    all_findings = []
    total_results = 0
    total_scanned = 0
    
    for name, query, _ in queries:
        if _RATE_LIMITED:
            print(f"  [rate-limited] Stopping — GitHub API limit reached")
            break
        
        print(f"\n  [dork] {name}: \"{query[:60]}...\"")
        results = search_code(query, github_token, max_pages=2)
        total_results += len(results)
        print(f"  [dork] Found {len(results)} code matches")
        
        if dry_run:
            for r in results[:5]:
                print(f"    {r['repo']} | {r['path']}")
            if len(results) > 5:
                print(f"    ... and {len(results) - 5} more")
            continue
        
        # Fetch and scan top results
        for i, r in enumerate(results[:max_scan]):
            if _RATE_LIMITED:
                break
            
            print(f"    [{i+1}/{min(len(results), max_scan)}] {r['repo']}/{r['path'][:40]}")
            
            content = fetch_file_content(r["repo"], r["path"], github_token)
            if not content:
                continue
            
            total_scanned += 1
            
            findings = scan_file_with_trufflehog(content, os.path.basename(r["path"]))
            if findings:
                for f in findings:
                    f["repo"] = r["repo"]
                    f["path"] = r["path"]
                    f["dork_name"] = name
                    f["dork_query"] = query
                    all_findings.append(f)
                    verified_str = "VERIFIED" if f.get("verified") else "unverified"
                    print(f"      [{verified_str}] {f['detector']}")
            
            time.sleep(1)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"[*] CODE DORKER SUMMARY")
    print(f"{'='*60}")
    print(f"  Queries run:         {len(queries)}")
    print(f"  Total code matches:  {total_results}")
    print(f"  Files scanned:       {total_scanned}")
    print(f"  Secrets found:       {len(all_findings)}")
    verified_count = sum(1 for f in all_findings if f.get("verified"))
    print(f"  Verified secrets:    {verified_count}")
    
    if json_out and all_findings:
        safe_findings = [{k: v for k, v in f.items() if k != "raw_secret"} for f in all_findings]
        with open(json_out, 'w') as f:
            json.dump(safe_findings, f, indent=2)
        print(f"  Results saved to:    {json_out}")
    
    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Search GitHub code for leaked secrets using dork queries"
    )
    parser.add_argument("--target", type=str, default="all",
                        choices=list(TARGET_GROUPS.keys()),
                        help="Target group (ai, cloud, github, payment, etc.)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Search only, don't fetch files or scan")
    parser.add_argument("--max-results", type=int, default=50,
                        help="Max results per query")
    parser.add_argument("--max-scan", type=int, default=20,
                        help="Max files to scan with TruffleHog")
    parser.add_argument("--json-out", type=str, default=None,
                        help="Save findings to JSON file")
    parser.add_argument("--github-token", type=str, default=None,
                        help="GitHub API token")
    
    args = parser.parse_args()
    github_token = args.github_token or os.environ.get("GITHUB_TOKEN")
    
    findings = run_code_dorker(
        target=args.target,
        dry_run=args.dry_run,
        max_results=args.max_results,
        max_scan=args.max_scan,
        github_token=github_token,
        json_out=args.json_out,
    )
    
    if findings:
        print(f"\n[*] Found {len(findings)} potential secrets!")
        verified = [f for f in findings if f.get("verified")]
        if verified:
            print(f"[*] {len(verified)} VERIFIED:")
            for f in verified:
                print(f"  - {f['detector']} in {f['repo']}/{f['path']}")


if __name__ == "__main__":
    main()
