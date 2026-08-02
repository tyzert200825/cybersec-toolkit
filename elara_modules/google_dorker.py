#!/usr/bin/env python3
"""
Google Dorking Scanner - Searches for exposed secrets using Google search operators.
Falls back to GitHub code search when Google is unavailable.

Targets: servers, websites, crypto wallets, crypto exchange API keys,
social media tokens (Facebook, Twitter, Instagram, Discord, Telegram, Snapchat, TikTok, LinkedIn, Reddit),
Australian telco credentials (Telstra, Optus, Vodafone AU), payment keys,
database connection strings, SSH keys, config files.

Usage:
    python3 google_dorker.py                    # Run all dork queries
    python3 google_dorker.py --output results.json
    python3 google_dorker.py --category crypto_exchange
    python3 google_dorker.py --github          # Use GitHub code search instead of Google
"""

import re
import json
import time
import sys
import os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote_plus
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret_patterns import PATTERNS, DORK_QUERIES

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def fetch_url(url, timeout=15, headers=None):
    """Fetch URL with browser headers."""
    h = {"User-Agent": UA, "Accept": "text/html,application/json,text/plain,*/*"}
    if headers:
        h.update(headers)
    try:
        req = Request(url, headers=h)
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

def search_google(query, max_results=10):
    """Search Google and extract result URLs."""
    search_url = f"https://www.google.com/search?q={quote_plus(query)}&num={max_results}"
    html = fetch_url(search_url)
    if not html:
        return []

    # Extract URLs from Google results
    urls = re.findall(r'href="/url\?q=([^&"]+)', html)
    if not urls:
        urls = re.findall(r'<a href="(https?://[^"]+)"', html)
    # Clean URLs
    clean = []
    for u in urls:
        if "google.com" in u or "googleapis.com" in u or "youtube.com" in u:
            continue
        clean.append(u.split("&")[0] if "&" in u else u)
    return list(set(clean))[:max_results]

def search_github_code(query, max_results=10, github_token=None):
    """Search GitHub code for patterns."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    api_url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page={max_results}"
    json_data = fetch_url(api_url, timeout=15, headers=headers)
    if not json_data:
        return []

    try:
        data = json.loads(json_data)
        results = []
        for item in data.get("items", []):
            results.append({
                "url": item.get("html_url", ""),
                "repo": item.get("repository", {}).get("full_name", ""),
                "file_path": item.get("path", ""),
                "raw_url": f"https://raw.githubusercontent.com/{item.get('repository', {}).get('full_name', '')}/master/{item.get('path', '')}"
            })
        return results
    except:
        return []

def fetch_content(url):
    """Fetch raw content from a URL."""
    return fetch_url(url, timeout=15)

def scan_content(content, source_url, query):
    """Scan content for secrets using all pattern categories."""
    findings = []
    for category, patterns in PATTERNS.items():
        for pat in patterns:
            matches = re.finditer(pat["regex"], content, re.IGNORECASE)
            for m in matches:
                secret_val = m.group(1) if m.groups() else m.group(0)
                start = max(0, m.start() - 50)
                end = min(len(content), m.end() + 50)
                context = content[start:end].replace("\n", " ").strip()

                finding = {
                    "search_query": query,
                    "source_url": source_url,
                    "category": category,
                    "secret_type": pat["name"],
                    "secret_value": secret_val,
                    "context": context,
                    "severity": pat["severity"],
                    "methods_of_use": pat["method"],
                    "disclosure_target": get_disclosure_target(pat["name"], category),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                findings.append(finding)
    return findings

def get_disclosure_target(name, category):
    """Determine who to report the finding to."""
    name_lower = name.lower()
    targets = {
        "binance": "Binance Security: security@binance.com",
        "coinbase": "Coinbase Security: https://www.coinbase.com/security",
        "kraken": "Kraken Security: security@kraken.com",
        "bybit": "Bybit Security: https://www.bybit.com/en/contactus",
        "kucoin": "Kucoin Security: https://www.kucoin.com/contact",
        "stripe": "Stripe Bug Bounty: https://hackerone.com/stripe",
        "paypal": "PayPal Security: https://www.paypal.com/security",
        "aws": "AWS Security: https://aws.amazon.com/security/",
        "telstra": "Telstra Security: https://www.telstra.com.au/security",
        "optus": "Optus Security: security@optus.com.au",
        "vodafone": "Vodafone AU Security: https://www.vodafone.com.au/security",
        "facebook": "Meta Security: https://www.meta.com/security/",
        "snapchat": "Snap Security: security@snap.com",
        "twitter": "Twitter/X Security: https://help.twitter.com/en/safety-and-security",
        "discord": "Discord Trust & Safety: https://discord.com/safety",
        "telegram": "Telegram Security: https://telegram.org/abuse",
        "instagram": "Instagram/Meta Security: https://help.instagram.com/368021276864178",
        "tiktok": "TikTok Security: https://www.tiktok.com/safety/en/",
        "linkedin": "LinkedIn Security: https://www.linkedin.com/help/linkedin/ask/TS-aha",
        "github": "GitHub Security: https://hackerone.com/github",
        "openai": "OpenAI Security: https://openai.com/security/",
        "google": "Google Security: https://bughunters.google.com",
    }
    for key, target in targets.items():
        if key in name_lower:
            return target
    if category in ("crypto_wallet", "crypto_exchange"):
        return "Contact exchange security team. For personal wallets, notify owner if identifiable."
    if category == "server_infrastructure":
        return "Notify infrastructure owner. For cloud providers, use their abuse reporting."
    if category == "payment":
        return "Contact payment provider security team immediately."
    if category == "telco_australian":
        return "Contact Australian telco security. Report via ACMA if systemic: https://www.acma.gov.au"
    if category == "database":
        return "Notify database owner immediately. Full credential exposure."
    if category == "social_media":
        return "Contact platform security team. Report compromised account."
    return "Check for bug bounty program on HackerOne or Bugcrowd."

def run_dork_scan(use_github=False, github_token=None, category_filter=None):
    """Run dork queries and scan results."""
    all_findings = []
    timestamp = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*60}")
    print(f"  GOOGLE DORKING SCANNER — Started {timestamp}")
    print(f"  Mode: {'GitHub Code Search' if use_github else 'Google Search'}")
    print(f"{'='*60}\n")

    categories = DORK_QUERIES.items()
    if category_filter:
        categories = [(category_filter, DORK_QUERIES.get(category_filter, []))]

    for cat_name, queries in categories:
        print(f"[*] Category: {cat_name} ({len(queries)} queries)")
        for query in queries:
            print(f"  [>] Dork: {query}")

            if use_github:
                results = search_github_code(query, max_results=5, github_token=github_token)
            else:
                results = search_google(query, max_results=10)

            if not results:
                print(f"  [-] No results")
                continue

            print(f"  [+] Found {len(results)} results")

            for result in results[:5]:
                if isinstance(result, dict):
                    url = result.get("raw_url") or result.get("url", "")
                else:
                    url = result

                if not url:
                    continue

                content = fetch_content(url)
                if content:
                    cat_findings = scan_content(content, url, query)
                    all_findings.extend(cat_findings)
                    if cat_findings:
                        print(f"  [!] SECRETS FOUND in {url}:")
                        for f in cat_findings:
                            print(f"      [{f['severity'].upper()}] {f['secret_type']}: {f['secret_value'][:50]}...")

                time.sleep(2)  # Rate limit between fetches

    # Deduplicate
    seen = set()
    unique = []
    for f in all_findings:
        key = (f["source_url"], f["secret_value"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"\n{'='*60}")
    print(f"  DORK SCAN COMPLETE")
    print(f"  Total findings: {len(unique)}")
    print(f"  Critical: {sum(1 for f in unique if f['severity'] == 'critical')}")
    print(f"  High: {sum(1 for f in unique if f['severity'] == 'high')}")
    print(f"  Medium: {sum(1 for f in unique if f['severity'] == 'medium')}")
    print(f"{'='*60}\n")

    for f in unique:
        print(f"  [{f['severity'].upper()}] {f['secret_type']}")
        print(f"    Value: {f['secret_value'][:60]}")
        print(f"    Source: {f['source_url']}")
        print(f"    Use: {f['methods_of_use'][:80]}...")
        print(f"    Report: {f['disclosure_target'][:60]}")
        print()

    return unique

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Google Dorking Scanner")
    parser.add_argument("--output", type=str, help="Save results to JSON file")
    parser.add_argument("--github", action="store_true", help="Use GitHub code search instead of Google")
    parser.add_argument("--category", type=str, help="Filter to specific category (e.g. crypto_exchange)")
    parser.add_argument("--token", type=str, help="GitHub API token for code search")
    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")

    findings = run_dork_scan(
        use_github=args.github,
        github_token=token,
        category_filter=args.category
    )

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(findings, fh, indent=2)
        print(f"[+] Results saved to {args.output}")
    elif findings:
        out = f"dork_findings_{int(time.time())}.json"
        with open(out, "w") as fh:
            json.dump(findings, fh, indent=2)
        print(f"[+] Results saved to {out}")

if __name__ == "__main__":
    main()
