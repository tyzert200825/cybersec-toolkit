#!/usr/bin/env python3
"""
GitHub Archive Secret Hunter
============================
Pipeline based on Yunus Aydın's approach:
https://aydinnyunus.github.io/2026/06/30/hunting-leaked-secrets-on-github-archive/

Regex-first, AI-fallback commit message filtering → diff fetch → TruffleHog verification.

Supports both old and new GH Archive formats, plus a GitHub Search API mode
for the new format (which no longer includes commit messages).

Usage:
    python3 gh_secret_hunter.py --dry-run                          # Filter current hour (dry run)
    python3 gh_secret_hunter.py --hour 2024-01-15-12               # Old format (has commit msgs)
    python3 gh_secret_hunter.py --search-mode                       # Use GitHub Search API
    python3 gh_secret_hunter.py --range 6                           # Hunt last 6 hours
    python3 gh_secret_hunter.py --json-out findings.json            # Save results to JSON
    python3 gh_secret_hunter.py --github-token ghp_xxx              # Use a GitHub token
"""

import argparse
import gzip
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote_plus

# ML classifier (optional — for AI-fallback on ambiguous commit messages)
try:
    from ml_secret_classifier import IntegratedClassifier, SecretClassifier
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False

# ─── Phase 2: Regex grammar stolen from the model ────────────────────────────

HIGH_CONFIDENCE_ACTION_VERBS = [
    "remove", "delete", "revoke", "invalidate", "rotate", "regenerate",
    "leak", "leaked", "expose", "exposed", "compromise", "compromised", "fix", "fixed",
]

HIGH_CONFIDENCE_OBJECT_NOUNS = [
    "api_key", "apikey", "api-key", "access_token", "auth_token",
    "private_key", "secret_key", "client_secret", "credential", "credentials",
    "password", "passwd", "aws_secret", "aws_access_key", "access_key",
    ".env", "dotenv", "token", "secret", "secrets",
    "ssh_key", "signing_key", "encryption_key",
    "service_account", "service_account_key",
    "firebase_key", "gcp_key", "azure_key",
]

BROAD_ACTION_VERBS = [
    "update", "change", "fix", "patch", "clean", "remove", "delete",
    "purge", "wipe", "scrub", "revert", "replace", "move", "rotate",
    "regenerate", "refactor", "strip", "sanitize", "redact", "obfuscate",
]

BROAD_OBJECT_NOUNS = [
    # Generic
    "key", "token", "secret", "password", "credential", "config", "configuration",
    "env", "environment", "auth", "oauth", "jwt",
    # Cloud providers
    "aws", "gcp", "azure", "firebase", "cloudflare", "digitalocean", "linode",
    "vultr", "hetzner", "oracle", "aliyun",
    # SaaS / APIs
    "stripe", "twilio", "mailgun", "sendgrid", "slack", "slackbot", "discord",
    "github", "gitlab", "bitbucket", "npm", "pypi", "docker", "hubspot",
    "datadog", "newrelic", "sentry", "pagerduty", "grafana", "prometheus",
    "algolia", "elastic", "mongodb", "redis", "postgres", "mysql",
    "supabase", "planetscale", "neon", "railway", "render", "vercel",
    "netlify", "heroku", "fly", "scaleway",
    # AI / ML
    "openai", "anthropic", "huggingface", "wandb", "weights_and_biases",
    "replicate", "together", "groq", "mistral", "cohere", "perplexity",
    # CI / CD
    "circleci", "travisci", "jenkins", "buildkite", "github_actions",
    "gitlab_ci", "drone", "argo", "tekton",
    # Payment / Finance
    "paypal", "square", "plaid", "coinbase", "binance",
    # Communication
    "vonage", "messagebird", "pusher", "ably",
    # Monitoring / Logging
    "sumologic", "splunk", "logz", "loggly", "papertrail",
    # Security
    "vault", "sops", "gpg", "age", "kms", "hsm",
    # Misc SaaS
    "airtable", "notion", "figma", "asana", "monday", "linear",
    "segment", "amplitude", "mixpanel", "posthog",
    "contentful", "sanity", "strapi", "shopify",
    "zoom", "webex", "intercom", "zendesk", "freshdesk",
]

# Three compiled regexes for canonical "I just leaked a secret" messages
SECRET_REMOVAL_PATTERNS = [
    re.compile(
        r'\b(remove|delete|revoke|invalidate|rotate|regenerate)\b.*\b(key|token|secret|password|credential)\b',
        re.IGNORECASE
    ),
    re.compile(
        r'\b(fix|patch)\b.*\b(leak|expose|compromise)\b',
        re.IGNORECASE
    ),
    re.compile(
        r'\b(revert)\b.*for.*security.*reason',
        re.IGNORECASE
    ),
]

# Pre-compile verb/noun sets for tier matching
_HC_VERBS = set(HIGH_CONFIDENCE_ACTION_VERBS)
_HC_NOUNS = set(HIGH_CONFIDENCE_OBJECT_NOUNS)
_BC_VERBS = set(BROAD_ACTION_VERBS)
_BC_NOUNS = set(BROAD_OBJECT_NOUNS)


def normalize(msg: str) -> str:
    """Normalize a commit message for keyword matching."""
    return re.sub(r'[^a-z0-9._\- ]', ' ', msg.lower()).replace('-', '_').replace('  ', ' ')


def has_word(text: str, word: str) -> bool:
    pattern = r'(?<![a-z0-9_])' + re.escape(word) + r'(?![a-z0-9_])'
    return bool(re.search(pattern, text))


def any_word(text: str, word_set: set) -> bool:
    for w in word_set:
        if has_word(text, w):
            return True
    return False


# ─── Phase 3: Regex-first, AI-fallback filter ────────────────────────────────

# Global integrated classifier instance (regex-first + ML-fallback)
_INTEGRATED_CLASSIFIER = None


def init_ml_classifier():
    """Initialize the ML classifier for AI-fallback."""
    global _INTEGRATED_CLASSIFIER
    if _ML_AVAILABLE:
        ml = SecretClassifier()
        if ml.load():
            _INTEGRATED_CLASSIFIER = IntegratedClassifier(ml_classifier=ml)
            print("  [ml] Loaded trained ML model for AI-fallback classification")
        else:
            print("  [ml] No trained model found — regex-only mode")
    return _INTEGRATED_CLASSIFIER


def classify_commit_message(msg: str) -> tuple[bool, str]:
    """
    Classify a commit message as suspicious of a secret leak.
    Returns (is_suspicious, reason).
    
    Uses regex-first, ML-fallback approach:
    - Tier 0/1: regex catches high-confidence patterns
    - Tier 2: regex catches broad patterns → still suspicious
    - Clean: no keyword match → not suspicious
    - If ML model is loaded, ambiguous tier2 messages get ML scoring
    """
    if not msg or not msg.strip():
        return False, "empty"
    
    # Use integrated classifier if available (regex + ML)
    if _INTEGRATED_CLASSIFIER:
        is_susp, reason, conf = _INTEGRATED_CLASSIFIER.classify(msg)
        return is_susp, reason
    
    # Fallback to regex-only
    normalized = normalize(msg)
    
    # Tier 0: Canonical secret-removal regex patterns
    for pattern in SECRET_REMOVAL_PATTERNS:
        if pattern.search(msg):
            return True, "tier0_regex"
    
    # Tier 1: High-confidence verb + high-confidence noun
    if any_word(normalized, _HC_VERBS) and any_word(normalized, _HC_NOUNS):
        return True, "tier1_high_confidence"
    
    # Tier 2: Broad verb + broad noun
    if any_word(normalized, _BC_VERBS) and any_word(normalized, _BC_NOUNS):
        return True, "tier2_broad"
    
    return False, "clean"


# ─── Phase 1: GH Archive downloader ──────────────────────────────────────────

GH_ARCHIVE_BASE = "https://data.gharchive.org"
GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "gh-secret-hunter/1.0"
_RATE_LIMITED = False


def generate_hour_keys(hours_back: int = 1, specific_hour: str = None) -> list[str]:
    if specific_hour:
        return [specific_hour]
    now = datetime.now(timezone.utc)
    keys = []
    for i in range(1, hours_back + 1):
        dt = now - timedelta(hours=i)
        keys.append(dt.strftime("%Y-%m-%d-%-H"))
    return keys


def download_archive(hour_key: str, dest_dir: str = "/tmp/gh_archive") -> str | None:
    os.makedirs(dest_dir, exist_ok=True)
    url = f"{GH_ARCHIVE_BASE}/{hour_key}.json.gz"
    gz_path = os.path.join(dest_dir, f"{hour_key}.json.gz")
    json_path = os.path.join(dest_dir, f"{hour_key}.json")
    
    if os.path.exists(json_path):
        print(f"  [cache] {hour_key} already downloaded")
        return json_path
    
    print(f"  [download] {url}")
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT})
        with urlopen(req) as resp:
            with open(gz_path, 'wb') as f:
                f.write(resp.read())
    except HTTPError as e:
        print(f"  [error] HTTP {e.code} for {url}")
        return None
    except URLError as e:
        print(f"  [error] {e.reason} for {url}")
        return None
    
    with gzip.open(gz_path, 'rb') as f_in:
        with open(json_path, 'wb') as f_out:
            f_out.write(f_in.read())
    os.remove(gz_path)
    size_mb = os.path.getsize(json_path) / (1024 * 1024)
    print(f"  [ok] {hour_key} ({size_mb:.1f} MB)")
    return json_path


def parse_events(json_path: str, event_types: set = None) -> list[dict]:
    if event_types is None:
        event_types = {"PushEvent", "PullRequestEvent"}
    
    events = []
    with open(json_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            event_type = event.get("type")
            if event_type not in event_types:
                continue
            
            if event_type == "PullRequestEvent":
                action = event.get("payload", {}).get("action")
                if action not in ("opened", "reopened"):
                    continue
            
            events.append(event)
    
    return events


def extract_commit_info(event: dict) -> list[dict]:
    """Extract commit messages and SHAs from an event. Handles both old and new GH Archive formats."""
    commits = []
    
    if event.get("type") == "PullRequestEvent":
        pr = event.get("payload", {}).get("pull_request", {})
        title = pr.get("title", "")
        if title:
            commits.append({
                "repo": event.get("repo", {}).get("name", ""),
                "message": title,
                "sha": pr.get("head", {}).get("sha", ""),
                "actor": event.get("actor", {}).get("login", ""),
                "event_type": "PullRequestEvent",
            })
        return commits
    
    # PushEvent
    repo_name = event.get("repo", {}).get("name", "")
    actor = event.get("actor", {}).get("login", "")
    payload = event.get("payload", {})
    
    # Old format: commits array with messages
    if "commits" in payload and payload["commits"]:
        for commit in payload["commits"]:
            sha = commit.get("sha", "")
            message = commit.get("message", "")
            if sha and message:
                commits.append({
                    "repo": repo_name,
                    "message": message,
                    "sha": sha,
                    "actor": actor,
                    "event_type": "PushEvent",
                })
    else:
        # New format: only head SHA, need to fetch commit message from API
        head_sha = payload.get("head", "")
        if head_sha:
            commits.append({
                "repo": repo_name,
                "message": "",  # Will be fetched from API
                "sha": head_sha,
                "actor": actor,
                "event_type": "PushEvent",
                "needs_api_fetch": True,
            })
    
    return commits


# ─── GitHub API helpers ──────────────────────────────────────────────────────

def github_api_get(url: str, github_token: str = None, accept: str = "application/vnd.github+json") -> dict | str | None:
    """Make a GitHub API GET request with proper headers."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": accept,
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    
    try:
        req = Request(url, headers=headers)
        with urlopen(req) as resp:
            data = resp.read()
            if accept == "application/vnd.github.v3.diff":
                return data.decode('utf-8', errors='replace')
            return json.loads(data)
    except HTTPError as e:
        if e.code == 403:
            # Rate limit check
            remaining = e.headers.get("X-RateLimit-Remaining", "?")
            reset = e.headers.get("X-RateLimit-Reset", "?")
            print(f"    [rate-limit] GitHub API rate limited (remaining: {remaining}, reset: {reset})")
        return None
    except Exception as e:
        print(f"    [error] {e}")
        return None


def fetch_commit_message(repo: str, sha: str, github_token: str = None) -> str | None:
    """Fetch a commit message from the GitHub API."""
    global _RATE_LIMITED
    if _RATE_LIMITED:
        return None
    url = f"{GITHUB_API_BASE}/repos/{repo}/commits/{sha}"
    result = github_api_get(url, github_token)
    if result is None:
        _RATE_LIMITED = True  # API call failed, likely rate limited
        return None
    if isinstance(result, dict):
        return result.get("commit", {}).get("message", "")
    return None


def fetch_diff(repo: str, sha: str, github_token: str = None) -> str | None:
    """Fetch the diff for a specific commit."""
    url = f"{GITHUB_API_BASE}/repos/{repo}/commits/{sha}"
    return github_api_get(url, github_token, accept="application/vnd.github.v3.diff")


def check_rate_limit(github_token: str = None) -> dict:
    """Check GitHub API rate limit status."""
    result = github_api_get(f"{GITHUB_API_BASE}/rate_limit", github_token)
    if result and isinstance(result, dict):
        core = result.get("resources", {}).get("core", {})
        search = result.get("resources", {}).get("search", {})
        return {
            "core_remaining": core.get("remaining", 0),
            "core_limit": core.get("limit", 0),
            "core_reset": core.get("reset", 0),
            "search_remaining": search.get("remaining", 0),
            "search_limit": search.get("limit", 0),
        }
    return {}


# ─── GitHub Search API mode ──────────────────────────────────────────────────

def search_suspicious_commits(github_token: str = None, max_pages: int = 10) -> list[dict]:
    """
    Use the GitHub Search API to find commits with suspicious messages.
    This works around the new GH Archive format that no longer includes commit messages.
    """
    # Search queries that match "I just leaked a secret" patterns
    search_queries = [
        "remove api key",
        "remove token secret",
        "delete credentials",
        "revoke api key",
        "rotate token",
        "remove leaked",
        "fix leaked secret",
        "remove password config",
        "revert secret",
        "purge credentials",
        "scrub token",
        "regenerate api key",
        "remove .env",
        "delete private key",
        "remove access token",
    ]
    
    all_results = []
    
    for query in search_queries:
        print(f"  [search] query: \"{query}\"")
        
        for page in range(1, max_pages + 1):
            encoded_query = quote_plus(query)
            url = (
                f"{GITHUB_API_BASE}/search/commits"
                f"?q={encoded_query}&sort=committer-date&order=desc"
                f"&per_page=100&page={page}"
            )
            
            result = github_api_get(url, github_token)
            if not result or not isinstance(result, dict):
                break
            
            items = result.get("items", [])
            if not items:
                break
            
            for item in items:
                commit = item.get("commit", {})
                repo = item.get("repository", {}).get("full_name", "")
                sha = item.get("sha", "")
                message = commit.get("message", "")
                
                if not sha or not repo:
                    continue
                
                # Verify with our regex filter
                is_suspicious, reason = classify_commit_message(message)
                
                all_results.append({
                    "repo": repo,
                    "message": message,
                    "sha": sha,
                    "actor": (item.get("author") or {}).get("login", "") if item.get("author") else "",
                    "event_type": "SearchAPI",
                    "reason": reason if is_suspicious else "search_match",
                    "date": commit.get("committer", {}).get("date", ""),
                })
            
            # Search API allows 30 requests/min, be conservative
            time.sleep(2)
            
            # Check if we've hit the last page
            total_count = result.get("total_count", 0)
            if page * 100 >= total_count:
                break
        
        print(f"  [search] found {len(all_results)} total so far")
    
    return all_results


# ─── Phase 4: TruffleHog verification ─────────────────────────────────────────

def run_trufflehog(diff_content: str, work_dir: str = None) -> list[dict]:
    """Run TruffleHog on raw diff content with verification enabled."""
    if work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="trufflehog_")
    
    diff_file = os.path.join(work_dir, "commit.diff")
    with open(diff_file, 'w', encoding='utf-8') as f:
        f.write(diff_content)
    
    cmd = [
        "trufflehog", "filesystem",
        work_dir,
        "--json",
        "--no-update",
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        print("    [timeout] TruffleHog timed out")
        return []
    except FileNotFoundError:
        print("    [error] TruffleHog not found")
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


# ─── Main pipeline ───────────────────────────────────────────────────────────

def run_pipeline(
    hours_back: int = 1,
    specific_hour: str = None,
    dry_run: bool = False,
    search_mode: bool = False,
    github_token: str = None,
    json_out: str = None,
    max_diffs: int = 50,
) -> list[dict]:
    
    # Initialize ML classifier for AI-fallback
    init_ml_classifier()
    
    all_findings = []
    total_commits = 0
    suspicious_commits = 0
    diffs_fetched = 0
    secrets_found = 0
    
    # ─── Search API mode ───
    if search_mode:
        print(f"\n[*] Mode: GitHub Search API")
        rl = check_rate_limit(github_token)
        if rl:
            print(f"  [rate-limit] core: {rl.get('core_remaining', '?')}/{rl.get('core_limit', '?')}, "
                  f"search: {rl.get('search_remaining', '?')}/{rl.get('search_limit', '?')}")
        
        print(f"  [search] Searching for suspicious commit messages...")
        flagged = search_suspicious_commits(github_token)
        suspicious_commits = len(flagged)
        print(f"  [search] Found {suspicious_commits} suspicious commits")
        
        if dry_run:
            for c in flagged[:20]:
                print(f"    [{c['reason']}] {c['repo']}@{c['sha'][:8]}: {c['message'][:80]}")
            if len(flagged) > 20:
                print(f"    ... and {len(flagged) - 20} more")
            return []
        
        # Fetch diffs + run TruffleHog
        seen = set()
        unique_flagged = []
        for c in flagged:
            key = f"{c['repo']}@{c['sha']}"
            if key not in seen:
                seen.add(key)
                unique_flagged.append(c)
        
        for i, commit in enumerate(unique_flagged[:max_diffs]):
            repo = commit["repo"]
            sha = commit["sha"]
            print(f"  [{i+1}/{min(len(unique_flagged), max_diffs)}] {repo}@{sha[:8]}: {commit['message'][:60]}")
            
            diff = fetch_diff(repo, sha, github_token)
            if not diff:
                continue
            diffs_fetched += 1
            
            findings = run_trufflehog(diff)
            if findings:
                for f in findings:
                    f["repo"] = repo
                    f["sha"] = sha
                    f["commit_message"] = commit["message"]
                    f["actor"] = commit.get("actor", "")
                    all_findings.append(f)
                    secrets_found += 1
                    verified_str = "VERIFIED" if f["verified"] else "unverified"
                    print(f"    [{verified_str}] {f['detector']}")
            
            time.sleep(1)  # Be nice to the API
    
    # ─── GH Archive mode ───
    else:
        hour_keys = generate_hour_keys(hours_back, specific_hour)
        print(f"\n[*] Mode: GH Archive")
        print(f"[*] Targeting {len(hour_keys)} hour(s): {', '.join(hour_keys)}")
        
        for hour_key in hour_keys:
            print(f"\n{'='*60}")
            print(f"[*] Processing hour: {hour_key}")
            print(f"{'='*60}")
            
            json_path = download_archive(hour_key)
            if not json_path:
                continue
            
            print(f"  [parse] Reading events...")
            events = parse_events(json_path)
            push_count = sum(1 for e in events if e.get("type") == "PushEvent")
            pr_count = sum(1 for e in events if e.get("type") == "PullRequestEvent")
            print(f"  [parse] {len(events)} events ({push_count} push, {pr_count} PR)")
            
            print(f"  [filter] Applying regex-first classification...")
            flagged = []
            needs_api_fetch = []
            
            for event in events:
                commits = extract_commit_info(event)
                for commit in commits:
                    total_commits += 1
                    
                    if commit.get("needs_api_fetch"):
                        # New format — need to fetch commit message from API
                        needs_api_fetch.append(commit)
                        continue
                    
                    is_suspicious, reason = classify_commit_message(commit["message"])
                    if is_suspicious:
                        suspicious_commits += 1
                        commit["reason"] = reason
                        flagged.append(commit)
            
            # Handle new-format events that need API calls
            if needs_api_fetch:
                print(f"  [filter] {len(needs_api_fetch)} commits need API fetch (new GH Archive format)")
                rl = check_rate_limit(github_token)
                api_budget = rl.get("core_remaining", 60)
                if github_token:
                    api_budget = min(api_budget, 5000)
                
                # Fetch commit messages for a sample
                fetch_count = min(len(needs_api_fetch), max(0, api_budget - 100), max_diffs * 3)
                print(f"  [filter] Fetching {fetch_count} commit messages from API (budget: {api_budget})...")
                
                for i, commit in enumerate(needs_api_fetch[:fetch_count]):
                    msg = fetch_commit_message(commit["repo"], commit["sha"], github_token)
                    if msg:
                        commit["message"] = msg
                        is_suspicious, reason = classify_commit_message(msg)
                        if is_suspicious:
                            suspicious_commits += 1
                            commit["reason"] = reason
                            commit.pop("needs_api_fetch", None)
                            flagged.append(commit)
                    
                    if (i + 1) % 100 == 0:
                        print(f"    [progress] {i+1}/{fetch_count} fetched, {len(flagged)} flagged")
                    
                    time.sleep(0.5)
                
                total_commits = total_commits - len(needs_api_fetch) + fetch_count
            
            print(f"  [filter] {suspicious_commits}/{total_commits} commits flagged as suspicious")
            
            if dry_run:
                print(f"  [dry-run] Skipping diff fetch + TruffleHog")
                for c in flagged[:20]:
                    print(f"    [{c['reason']}] {c['repo']}@{c['sha'][:8]}: {c['message'][:80]}")
                if len(flagged) > 20:
                    print(f"    ... and {len(flagged) - 20} more")
                continue
            
            # Fetch diffs + run TruffleHog
            seen = set()
            unique_flagged = []
            for c in flagged:
                key = f"{c['repo']}@{c['sha']}"
                if key not in seen:
                    seen.add(key)
                    unique_flagged.append(c)
            
            for i, commit in enumerate(unique_flagged[:max_diffs]):
                repo = commit["repo"]
                sha = commit["sha"]
                print(f"  [{i+1}/{min(len(unique_flagged), max_diffs)}] {repo}@{sha[:8]}: {commit['message'][:60]}")
                
                diff = fetch_diff(repo, sha, github_token)
                if not diff:
                    continue
                diffs_fetched += 1
                
                findings = run_trufflehog(diff)
                if findings:
                    for f in findings:
                        f["repo"] = repo
                        f["sha"] = sha
                        f["commit_message"] = commit["message"]
                        f["actor"] = commit.get("actor", "")
                        f["hour"] = hour_key
                        all_findings.append(f)
                        secrets_found += 1
                        verified_str = "VERIFIED" if f["verified"] else "unverified"
                        print(f"    [{verified_str}] {f['detector']}")
                
                time.sleep(0.5)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"[*] PIPELINE SUMMARY")
    print(f"{'='*60}")
    print(f"  Total commits scanned: {total_commits}")
    print(f"  Suspicious commits:    {suspicious_commits}")
    print(f"  Diffs fetched:         {diffs_fetched}")
    print(f"  Secrets found:         {secrets_found}")
    verified_count = sum(1 for f in all_findings if f.get("verified"))
    print(f"  Verified secrets:      {verified_count}")
    
    if json_out and all_findings:
        safe_findings = []
        for f in all_findings:
            sf = {k: v for k, v in f.items() if k != "raw_secret"}
            safe_findings.append(sf)
        with open(json_out, 'w') as f:
            json.dump(safe_findings, f, indent=2)
        print(f"  Results saved to:      {json_out}")
    
    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Hunt leaked secrets on GitHub Archive (regex-first, AI-fallback, TruffleHog verification)"
    )
    parser.add_argument("--hour", type=str, default=None,
                        help="Specific hour to process (format: YYYY-MM-DD-H)")
    parser.add_argument("--range", type=int, default=1,
                        help="Number of hours to process (back from now)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Filter only, don't fetch diffs or run TruffleHog")
    parser.add_argument("--search-mode", action="store_true",
                        help="Use GitHub Search API instead of GH Archive (works with new format)")
    parser.add_argument("--json-out", type=str, default=None,
                        help="Save findings to JSON file")
    parser.add_argument("--max-diffs", type=int, default=50,
                        help="Maximum number of diffs to fetch per run")
    parser.add_argument("--github-token", type=str, default=None,
                        help="GitHub API token (for higher rate limits)")
    
    args = parser.parse_args()
    github_token = args.github_token or os.environ.get("GITHUB_TOKEN")
    
    findings = run_pipeline(
        hours_back=args.range,
        specific_hour=args.hour,
        dry_run=args.dry_run,
        search_mode=args.search_mode,
        github_token=github_token,
        json_out=args.json_out,
        max_diffs=args.max_diffs,
    )
    
    if findings:
        print(f"\n[*] Found {len(findings)} potential secrets!")
        verified = [f for f in findings if f.get("verified")]
        if verified:
            print(f"[*] {len(verified)} VERIFIED live secrets:")
            for f in verified:
                print(f"  - {f['detector']} in {f['repo']}@{f['sha'][:8]}")
    else:
        print("\n[*] No secrets found in this batch.")


if __name__ == "__main__":
    main()
