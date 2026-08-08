# Elara SecOps — Secret Hunter

Complete secret hunting pipeline for discovering leaked credentials across GitHub, paste sites, and Google dorking targets. Built for bounty-focused disclosure reporting with full unredacted secret storage.

## Structure

```
secret-hunter/
├── config/
│   └── secret_patterns.py      # 73 regex patterns across 10 categories
├── scanners/
│   ├── gh_secret_hunter.py     # GitHub Archive commit scanner (Yunus Aydın method)
│   ├── google_dorker.py        # Google dorking + GitHub code search fallback
│   ├── paste_monitor.py        # Paste site monitor (Pastebin, Gists, Rentry)
│   ├── code_dorker.py          # GitHub Code Search API dorker
│   ├── oops_scanner.py         # Deleted commit scanner (force-push recovery)
│   ├── pandas_scanner.py       # Pandas-powered bulk scanner with exports
│   └── ml_secret_classifier.py # TF-IDF + Logistic Regression fallback classifier
├── verifiers/
│   └── verify_secrets.py       # Secret verification (Google OAuth, AWS, etc.)
├── dashboard/
│   ├── admin_dashboard.html    # Self-contained web dashboard (no backend needed)
│   └── pipeline_server.py      # Local pipeline server + dashboard host
├── hardware/
│   ├── hardware_scanner.py     # Hardware interface scanner (Serial, I2C, SPI, USB, etc.)
│   └── smart_crop.py            # Image cropping utility
├── backend/                     # Base44 serverless backend functions
│   ├── runPipeline.ts          # Main pipeline orchestrator
│   ├── cryptoScan.ts           # Crypto exchange/wallet secret scanner
│   ├── websiteScan.ts          # Website vulnerability scanner
│   ├── coldcardMonitor.ts      # Coldcard RNG exploit wallet tracker
│   ├── scanDashboard.ts        # Dashboard data server
│   ├── getSecretFindings.ts    # Findings API endpoint
│   ├── secureDashboard.ts      # Password-free dashboard proxy
│   └── adminAuth.ts            # Auth function (no-auth version)
├── termux/
│   └── termux_cybersec_install.sh  # Android/Termux installer
├── data/                        # Saved findings and reports
├── requirements.txt
└── setup.sh
```

## Pattern Categories

| Category | Patterns | Targets |
|----------|----------|---------|
| crypto_exchange | 12 | Binance, Coinbase, Kraken, Bybit, Kucoin, Bisq, Coinspot |
| crypto_wallet | 8 | BTC/ETH/SOL private keys, seed phrases, wallet.dat |
| social_media | 14 | Facebook, Twitter, Instagram, Discord, Telegram, Snapchat, TikTok, LinkedIn, Reddit |
| telco_australian | 5 | Telstra, Optus, Vodafone AU, Twilio |
| server_infrastructure | 8 | AWS, GCP, Azure, DigitalOcean, SSH keys |
| database | 6 | MongoDB, PostgreSQL, MySQL, Redis |
| payment | 5 | Stripe, PayPal, Square, Razorpay |
| google_accounts | 6 | OAuth, Service Account, API key, Firebase, GCP |
| microsoft_accounts | 5 | Azure AD, Graph, Outlook, Teams, Azure Storage |
| ai_services | 4 | OpenAI, Anthropic, HuggingFace, Replicate |

**Total: 73 regex patterns, 87 Google dork queries, 30 GitHub code dorks**

## Quick Start

```bash
# Setup
bash setup.sh
export GITHUB_TOKEN=ghp_your_token_here

# Run scanners
python3 scanners/gh_secret_hunter.py --range 6          # Last 6 hours of GH Archive
python3 scanners/google_dorker.py --github              # GitHub code search
python3 scanners/paste_monitor.py --continuous          # Monitor paste sites
python3 scanners/code_dorker.py --dorks all             # GitHub code dorking
python3 scanners/oops_scanner.py --range 24             # Deleted commits (24h)

# Start dashboard
python3 dashboard/pipeline_server.py                    # Local dashboard on :9191

# Termux (Android)
bash termux/termux_cybersec_install.sh
```

## Pipeline Flow

1. **Commit Filtering** (gh_secret_hunter.py) — Downloads GH Archive, filters commit messages with regex tiers, uses ML fallback for ambiguous messages
2. **Diff Fetching** — Fetches .patch URLs to bypass API rate limits
3. **Secret Detection** — 73 regex patterns across 10 categories
4. **Verification** (verify_secrets.py) — Validates secrets against provider APIs
5. **Storage** — Full unredacted secrets with method-of-use, impact assessment, disclosure targets, and bounty info
6. **Dashboard** — Real-time display with filtering, CSV/JSON export

## Bounty Programs

Findings are tagged with bounty programs:
- Google VRP: $500–$31,000
- AWS Security: $100–$10,000
- Microsoft MSRC: $500–$20,000
- Notify Owner: $100–$10,000
- Stripe: $500–$15,000

## Coldcard Monitoring

The Coldcard Monitor tracks BTC addresses associated with the RNG exploit waves:
- Wave 1: 562 BTC consolidated (bc1qnk prefix)
- Wave 2: Shared collector addresses
- Wave 3: Individual P2WSH addresses (4,585 total)

Monitors balance, transaction count, and activity status via mempool.space API.

## Backend Deployment

The `backend/` folder contains Deno/TypeScript functions for Base44 serverless deployment:

```bash
# Deploy via Base44 CLI or platform
deno run --allow-net backend/runPipeline.ts    # Pipeline orchestrator
deno run --allow-net backend/cryptoScan.ts      # Crypto secret scanner
deno run --allow-net backend/coldcardMonitor.ts # Coldcard wallet tracker
```

## Environment Variables

```bash
GITHUB_TOKEN=ghp_xxx          # GitHub API token (required for scanners)
SHODAN_API_KEY=xxx            # Shodan API key (optional, for infra scanning)
```

## Standing Instructions

- All findings stored with full unredacted secret values
- Each finding includes: secret value, method of use, impact assessment, disclosure target
- Daily automated scans at 9:00 AM Sydney time
- WhatsApp alerts for critical findings
- Separate pipelines for secret hunting vs crypto scanning
