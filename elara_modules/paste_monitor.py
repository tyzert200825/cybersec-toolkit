#!/usr/bin/env python3
"""
Paste Site Monitor - Scans paste sites for leaked secrets and credentials.
Targets: Pastebin, Rentry, GitHub Gists, Paste.ee

Detects: crypto exchange API keys, wallet private keys/seed phrases,
social media tokens (Facebook, Twitter, Instagram, Discord, Telegram, Snapchat, TikTok, LinkedIn, Reddit),
Australian telco credentials (Telstra, Optus, Vodafone AU, Twilio),
server credentials (AWS, GCP, Azure, SSH keys), database connection strings,
payment keys (Stripe, PayPal, Square), email:password combos, and more.

Usage:
    python3 paste_monitor.py                    # One-time scan
    python3 paste_monitor.py --continuous       # Loop every 60 seconds
    python3 paste_monitor.py --output results.json
"""

import re
import json
import time
import sys
import os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret_patterns import PATTERNS, DORK_QUERIES

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def fetch_url(url, timeout=15):
    try:
        req = Request(url, headers={
            "User-Agent": UA,
            "Accept": "text/html,application/json,text/plain,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

def get_disclosure_target(name, category):
    name_lower = name.lower()
    targets = {
        "bitcoin": "No central authority - notify wallet owner. For exchange keys, contact exchange security team.",
        "ethereum": "No central authority - notify wallet owner. For exchange keys, contact exchange security team.",
        "solana": "No central authority - notify wallet owner. For exchange keys, contact exchange security team.",
        "seed": "No central authority - notify wallet owner. Seed phrases drain all crypto assets.",
        "binance": "Binance Security: security@binance.com or https://binance.com/en/security",
        "coinbase": "Coinbase Security: https://www.coinbase.com/security or security@coinbase.com",
        "kraken": "Kraken Security: security@kraken.com",
        "bybit": "Bybit Security: https://www.bybit.com/en/contactus",
        "kucoin": "Kucoin Security: https://www.kucoin.com/contact",
        "stripe": "Stripe Security: https://stripe.com/security or https://hackerone.com/stripe",
        "paypal": "PayPal Security: https://www.paypal.com/security",
        "square": "Square Security: https://squareup.com/help/us/en",
        "aws": "AWS Security: https://aws.amazon.com/security/ or aws-security@amazon.com",
        "telstra": "Telstra Security: https://www.telstra.com.au/security",
        "optus": "Optus Security: security@optus.com.au",
        "vodafone": "Vodafone AU Security: https://www.vodafone.com.au/security",
        "facebook": "Meta Security: https://www.meta.com/security/",
        "snapchat": "Snap Security: security@snap.com or https://snap.com/en-US/privacy",
        "twitter": "Twitter/X Security: https://help.twitter.com/en/safety-and-security",
        "discord": "Discord Security: https://discord.com/safety",
        "telegram": "Telegram Security: https://telegram.org/abuse",
        "instagram": "Instagram/Meta Security: https://help.instagram.com/368021276864178",
        "tiktok": "TikTok Security: https://www.tiktok.com/safety/en/",
        "linkedin": "LinkedIn Security: https://www.linkedin.com/help/linkedin/ask/TS-aha",
        "reddit": "Reddit Security: https://www.reddit.com/report",
        "github": "GitHub Security: https://hackerone.com/github",
        "google": "Google Security: https://bughunters.google.com",
        "openai": "OpenAI Security: https://openai.com/security/ or https://hackerone.com/openai",
        "slack": "Slack Security: https://slack.com/trust/security",
        "heroku": "Heroku Security: https://www.heroku.com/policy/security",
        "digitalocean": "DigitalOcean Security: https://www.digitalocean.com/security",
        "azure": "Azure Security: https://portal.mscrm.com/security",
    }
    for key, target in targets.items():
        if key in name_lower:
            return target
    if category == "server_infrastructure":
        return "Notify infrastructure owner. For cloud providers, use their abuse reporting."
    if category == "database":
        return "Notify database owner immediately. Full credential exposure."
    if category == "payment":
        return "Contact payment provider security team immediately."
    if category == "social_media":
        return "Contact platform security team. Report compromised account."
    if category == "telco_australian":
        return "Contact Australian telco security. Report via ACMA if systemic: https://www.acma.gov.au"
    return "Check for bug bounty program on HackerOne or Bugcrowd."

def extract_pastebin_links(html):
    if not html:
        return []
    links = re.findall(r'href="/([A-Za-z0-9]{8,15})"', html)
    valid = [l for l in links if len(l) >= 8 and not l.startswith('archive')
             and l not in ('pro', 'api', 'tools', 'faq', 'login', 'signup', 'contact')]
    return list(set(valid))[:30]

def extract_rentry_pages(html):
    if not html:
        return []
    slugs = re.findall(r'href="/([a-z0-9-]{3,50})"', html)
    return list(set(slugs))[:20]

def extract_gist_links(json_data):
    if not json_data:
        return []
    try:
        gists = json.loads(json_data)
        urls = []
        for g in gists:
            for fname, fdata in g.get("files", {}).items():
                if fdata.get("raw_url"):
                    urls.append(fdata["raw_url"])
        return urls[:30]
    except:
        return []

def scan_content(content, source_url, source_site):
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
                    "source_url": source_url,
                    "source_site": source_site,
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

def scan_pastebin():
    findings = []
    print("[*] Scanning Pastebin archive...")
    html = fetch_url("https://pastebin.com/archive")
    if not html:
        print("  [-] Failed to fetch Pastebin archive")
        return findings
    paste_ids = extract_pastebin_links(html)
    print(f"  [+] Found {len(paste_ids)} recent pastes")
    for pid in paste_ids:
        paste_url = f"https://pastebin.com/raw/{pid}"
        content = fetch_url(paste_url, timeout=10)
        if content:
            paste_findings = scan_content(content, paste_url, "pastebin")
            findings.extend(paste_findings)
            if paste_findings:
                print(f"  [!] Found {len(paste_findings)} secrets in paste {pid}")
        time.sleep(2)
    return findings

def scan_rentry():
    findings = []
    print("[*] Scanning Rentry.co...")
    html = fetch_url("https://rentry.co/recent")
    if not html:
        print("  [-] Failed to fetch Rentry recent")
        return findings
    slugs = extract_rentry_pages(html)
    print(f"  [+] Found {len(slugs)} recent entries")
    for slug in slugs:
        page_url = f"https://rentry.co/{slug}/raw"
        content = fetch_url(page_url, timeout=10)
        if content:
            page_findings = scan_content(content, page_url, "rentry")
            findings.extend(page_findings)
            if page_findings:
                print(f"  [!] Found {len(page_findings)} secrets in rentry/{slug}")
        time.sleep(1)
    return findings

def scan_gists():
    findings = []
    print("[*] Scanning GitHub public gists...")
    json_data = fetch_url("https://api.github.com/gists/public?per_page=30", timeout=15)
    if not json_data:
        print("  [-] Failed to fetch gists (rate limit?)")
        return findings
    gist_urls = extract_gist_links(json_data)
    print(f"  [+] Found {len(gist_urls)} gist files")
    for url in gist_urls:
        content = fetch_url(url, timeout=10)
        if content:
            gist_findings = scan_content(content, url, "github_gist")
            findings.extend(gist_findings)
            if gist_findings:
                print(f"  [!] Found {len(gist_findings)} secrets in gist file")
        time.sleep(2)
    return findings

def scan_pastee():
    findings = []
    print("[*] Scanning Paste.ee...")
    html = fetch_url("https://paste.ee/recent")
    if not html:
        print("  [-] Failed to fetch Paste.ee (may be offline)")
        return findings
    paste_ids = re.findall(r'href="/p/([a-zA-Z0-9]+)"', html)
    paste_ids = list(set(paste_ids))[:20]
    print(f"  [+] Found {len(paste_ids)} recent pastes")
    for pid in paste_ids:
        raw_url = f"https://paste.ee/r/{pid}"
        content = fetch_url(raw_url, timeout=10)
        if content:
            paste_findings = scan_content(content, raw_url, "paste_ee")
            findings.extend(paste_findings)
            if paste_findings:
                print(f"  [!] Found {len(paste_findings)} secrets in paste.ee/{pid}")
        time.sleep(1)
    return findings

def run_scan():
    all_findings = []
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"\n{'='*60}")
    print(f"  PASTE SITE MONITOR - Scan started {timestamp}")
    print(f"{'='*60}")
    all_findings.extend(scan_pastebin())
    all_findings.extend(scan_rentry())
    all_findings.extend(scan_gists())
    all_findings.extend(scan_pastee())

    seen = set()
    unique = []
    for f in all_findings:
        key = (f["source_url"], f["secret_value"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"  Total findings: {len(unique)}")
    print(f"  Critical: {sum(1 for f in unique if f['severity'] == 'critical')}")
    print(f"  High: {sum(1 for f in unique if f['severity'] == 'high')}")
    print(f"  Medium: {sum(1 for f in unique if f['severity'] == 'medium')}")
    print(f"{'='*60}\n")

    for f in unique:
        print(f"  [{f['severity'].upper()}] {f['secret_type']}")
        print(f"    Secret: {f['secret_value'][:60]}...")
        print(f"    Source: {f['source_url']}")
        print(f"    Method: {f['methods_of_use'][:80]}...")
        print(f"    Report: {f['disclosure_target']}")
        print()
    return unique

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Paste Site Monitor")
    parser.add_argument("--continuous", action="store_true", help="Run continuously (60s intervals)")
    parser.add_argument("--output", type=str, help="Save results to JSON file")
    args = parser.parse_args()

    if args.continuous:
        print("[*] Continuous mode. Scanning every 60 seconds. Ctrl+C to stop.")
        while True:
            findings = run_scan()
            if args.output:
                with open(args.output, "w") as fh:
                    json.dump(findings, fh, indent=2)
            print("[*] Sleeping 60 seconds...")
            time.sleep(60)
    else:
        findings = run_scan()
        if args.output:
            with open(args.output, "w") as fh:
                json.dump(findings, fh, indent=2)
            print(f"[+] Results saved to {args.output}")
        elif findings:
            out = f"paste_findings_{int(time.time())}.json"
            with open(out, "w") as fh:
                json.dump(findings, fh, indent=2)
            print(f"[+] Results saved to {out}")

if __name__ == "__main__":
    main()
