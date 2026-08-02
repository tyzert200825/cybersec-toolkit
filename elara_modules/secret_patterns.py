"""
Secret detection patterns organized by category.
Used by paste_monitor.py and google_dorker.py
"""

PATTERNS = {
    "crypto_exchange": [
        # Binance
        {"name": "Binance API Key", "regex": r"BINANCE[_]?API[_]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{64})['\"]?", "severity": "critical", "method": "Binance API key for trading/withdrawal. Pair with secret key to execute trades, check balances, and withdraw funds."},
        {"name": "Binance Secret Key", "regex": r"BINANCE[_]?SECRET[_]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{64})['\"]?", "severity": "critical", "method": "Binance secret key - signs API requests. Combined with API key allows full account control including withdrawals."},
        # Coinbase
        {"name": "Coinbase API Key", "regex": r"COINBASE[_]?API[_]?KEY\s*[=:]\s*['\"]?([a-f0-9]{24,64})['\"]?", "severity": "critical", "method": "Coinbase API key for account access, trading, and wallet operations."},
        {"name": "Coinbase Secret", "regex": r"COINBASE[_]?API[_]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{24,64})['\"]?", "severity": "critical", "method": "Coinbase API secret - signs requests for trading and withdrawal endpoints."},
        # Kraken
        {"name": "Kraken API Key", "regex": r"KRAKEN[_]?API[_]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{56})['\"]?", "severity": "critical", "method": "Kraken API key for trading and account access."},
        {"name": "Kraken API Secret", "regex": r"KRAKEN[_]?API[_]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{86})['\"]?", "severity": "critical", "method": "Kraken API private key - signs requests for trading, withdrawals, and balance queries."},
        # Bybit
        {"name": "Bybit API Key", "regex": r"BYBIT[_]?API[_]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{36})['\"]?", "severity": "critical", "method": "Bybit exchange API key for derivatives trading and withdrawals."},
        # Kucoin
        {"name": "Kucoin API Key", "regex": r"KUCOIN[_]?API[_]?KEY\s*[=:]\s*['\"]?([a-f0-9]{24})['\"]?", "severity": "critical", "method": "Kucoin API key for spot/futures trading."},
        {"name": "Kucoin API Secret", "regex": r"KUCOIN[_]?API[_]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9-]{36})['\"]?", "severity": "critical", "method": "Kucoin API secret - signs requests for trading and withdrawals."},
        # FTX
        {"name": "FTX API Key", "regex": r"FTX[_]?API[_]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{32})['\"]?", "severity": "high", "method": "FTX exchange API key (FTX is defunct but keys may still be traded)."},
    ],

    "crypto_wallet": [
        {"name": "Bitcoin Private Key (WIF)", "regex": r"\b([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b", "severity": "critical", "method": "Bitcoin private key in Wallet Import Format. Can import into any wallet to spend all funds. Direct financial loss."},
        {"name": "Ethereum Private Key", "regex": r"\b(0x[a-fA-F0-9]{64})\b", "severity": "critical", "method": "Ethereum private key. Import to MetaMask or any ETH wallet to drain all ETH, ERC-20 tokens, and NFTs from the address."},
        {"name": "Solana Private Key", "regex": r"\b([1-9A-HJ-NP-Za-km-z]{87,88})\b", "severity": "critical", "method": "Possible Solana private key (base58, 88 chars). Can import to Phantom wallet to drain SOL and SPL tokens."},
        {"name": "Seed Phrase (12 words)", "regex": r"\b((?:[a-z]{3,8}\s){11}[a-z]{3,8})\b", "severity": "critical", "method": "12-word BIP39 mnemonic seed phrase. Can restore any crypto wallet (Bitcoin, Ethereum, Solana, etc.) and drain all funds across all derived addresses."},
        {"name": "Seed Phrase (24 words)", "regex": r"\b((?:[a-z]{3,8}\s){23}[a-z]{3,8})\b", "severity": "critical", "method": "24-word BIP39 mnemonic seed phrase. Full wallet recovery - drains all cryptocurrencies and NFTs across all accounts."},
        {"name": "Wallet Dat File", "regex": r"wallet\.dat", "severity": "high", "method": "Reference to wallet.dat file - Bitcoin Core wallet. Contains private keys for all addresses."},
    ],

    "social_media": [
        {"name": "Facebook Access Token", "regex": r"\b(EAAG[a-zA-Z0-9]{20,})\b", "severity": "high", "method": "Facebook Graph API access token. Can read user profile, posts, messages, and post on behalf of the user."},
        {"name": "Facebook App Secret", "regex": r"FACEBOOK[_]?APP[_]?SECRET\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", "severity": "high", "method": "Facebook app secret - signs API requests for the app. Can generate access tokens for any app user."},
        {"name": "Twitter Bearer Token", "regex": r"\b(AAAA[a-zA-Z0-9]{%1,40})\b", "severity": "high", "method": "Twitter/X API bearer token. App-level access to Twitter API - read tweets, DMs, user data."},
        {"name": "Twitter Consumer Secret", "regex": r"TWITTER[_]?CONSUMER[_]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9]{40,50})['\"]?", "severity": "high", "method": "Twitter consumer secret - signs OAuth requests. Can generate access tokens for any Twitter user."},
        {"name": "Instagram Access Token", "regex": r"INSTAGRAM[_]?ACCESS[_]?TOKEN\s*[=:]\s*['\"]?(IGQVJ[A-Za-z0-9_]{20,})['\"]?", "severity": "high", "method": "Instagram Graph API token. Can read profile, posts, stories, and DMs."},
        {"name": "Discord Bot Token", "regex": r"\b([A-Za-z0-9]{24}\.[A-Za-z0-9_]{6}\.[A-Za-z0-9_]{27})\b", "severity": "high", "method": "Discord bot token. Full control of the bot account - read messages, send messages, access guilds."},
        {"name": "Discord Webhook URL", "regex": r"(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)", "severity": "medium", "method": "Discord webhook URL. Can send messages to the channel without authentication."},
        {"name": "Telegram Bot Token", "regex": r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33,35})\b", "severity": "high", "method": "Telegram bot token. Full control of the bot - send messages, read chats, access group data."},
        {"name": "Snapchat API Token", "regex": r"SNAPCHAT[_]?API[_]?TOKEN\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", "severity": "high", "method": "Snapchat API token. Access to Snapchat Marketing API or Snap Kit - can access user data, ad accounts, and campaign data."},
        {"name": "Snapchat Client Secret", "regex": r"SNAPCHAT[_]?CLIENT[_]?SECRET\s*[=:]\s*['\"]?([a-f0-9]{32,64})['\"]?", "severity": "high", "method": "Snapchat OAuth client secret. Can generate access tokens for Snapchat users via Snap Login Kit."},
        {"name": "Reddit API Secret", "regex": r"REDDIT[_]?API[_]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9]{27})['\"]?", "severity": "medium", "method": "Reddit API client secret. Access to Reddit API for reading/moderating subreddits."},
        {"name": "TikTok Access Token", "regex": r"TIKTOK[_]?ACCESS[_]?TOKEN\s*[=:]\s*['\"]?(tt[A-Za-z0-9_]{20,})['\"]?", "severity": "high", "method": "TikTok API access token. Can read user profile, video data, and post content."},
        {"name": "LinkedIn Access Token", "regex": r"LINKEDIN[_]?ACCESS[_]?TOKEN\s*[=:]\s*['\"]?(AQ[A-Za-z0-9_]{20,})['\"]?", "severity": "high", "method": "LinkedIn API access token. Can read profile, connections, and post on behalf of user."},
    ],

    "telco_australian": [
        {"name": "Telstra API Key", "regex": r"TELSTRA[_]?API[_]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{20,})['\"]?", "severity": "high", "method": "Telstra API key - access to Telstra dev APIs including SMS, voice, and messaging services."},
        {"name": "Telstra OAuth Secret", "regex": r"TELSTRA[_]?CLIENT[_]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9]{20,})['\"]?", "severity": "high", "method": "Telstra OAuth client secret - can generate access tokens for Telstra API services."},
        {"name": "Optus API Key", "regex": r"OPTUS[_]?API[_]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{20,})['\"]?", "severity": "high", "method": "Optus API key - access to Optus mobile and internet service APIs."},
        {"name": "Vodafone AU API Key", "regex": r"VODAFONE[_]?AU[_]?API[_]?KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{20,})['\"]?", "severity": "high", "method": "Vodafone Australia API key - access to Vodafone AU mobile account services."},
        {"name": "Australian Phone + Password", "regex": r"(\+61[4-5][0-9]{8})\s*[:\s]+\s*([A-Za-z0-9!@#$%^&*]{6,})", "severity": "high", "method": "Australian mobile number with associated password. Could be used for SIM swap attacks or account takeover on telco services."},
        {"name": "Twilio Auth Token", "regex": r"TWILIO[_]?AUTH[_]?TOKEN\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", "severity": "high", "method": "Twilio auth token - can send SMS, make calls, and access account data via Twilio API."},
        {"name": "Twilio Account SID", "regex": r"TWILIO[_]?ACCOUNT[_]?SID\s*[=:]\s*['\"]?(AC[a-f0-9]{32})['\"]?", "severity": "medium", "method": "Twilio account SID - identifier for Twilio account. Combined with auth token gives full API access."},
    ],

    "server_infrastructure": [
        {"name": "AWS Access Key ID", "regex": r"\b(AKIA[0-9A-Z]{16})\b", "severity": "critical", "method": "AWS access key ID. Combined with secret access key gives full AWS account access - S3, EC2, RDS, IAM, Secrets Manager, Lambda, everything."},
        {"name": "AWS Secret Access Key", "regex": r"aws[_]?secret[_]?access[_]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "severity": "critical", "method": "AWS secret access key - signs all AWS API requests. Full account compromise when paired with access key ID."},
        {"name": "AWS Session Token", "regex": r"aws[_]?session[_]?token\s*[=:]\s*['\"]?(Fwo[A-Za-z0-9+/=]{50,})['\"]?", "severity": "critical", "method": "AWS temporary session token from STS. Grants short-lived but full AWS access."},
        {"name": "Private Key Block", "regex": r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)", "severity": "critical", "method": "Private key file - SSH, SSL/TLS, or PGP. Can authenticate to servers, decrypt traffic, or sign messages as the key owner."},
        {"name": "DigitalOcean Token", "regex": r"DIGITALOCEAN[_]?TOKEN\s*[=:]\s*['\"]?(dop_v1_[a-f0-9]{64})['\"]?", "severity": "high", "method": "DigitalOcean personal access token - full control of droplets, DNS, storage, and networking."},
        {"name": "GCP Service Account Key", "regex": r"(\"type\":\s*\"service_account\"[\s\S]*?\"private_key\":\s*\"(-----BEGIN PRIVATE KEY-----[^\"]+)\"[\s\S]*?})", "severity": "critical", "method": "GCP service account JSON key - full access to Google Cloud project including GCS, GCE, BigQuery, and IAM."},
        {"name": "Azure Connection String", "regex": r"(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+)", "severity": "high", "method": "Azure Storage connection string - direct access to Azure blob, table, and queue storage."},
        {"name": "Heroku API Key", "regex": r"HEROKU[_]?API[_]?KEY\s*[=:]\s*['\"]?([a-f0-9]{32,64})['\"]?", "severity": "high", "method": "Heroku API key - manage apps, dynos, add-ons, and config vars including environment secrets."},
    ],

    "database": [
        {"name": "MongoDB Connection String", "regex": r"(mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s\"']+)", "severity": "critical", "method": "MongoDB connection string with credentials. Direct database access - read, write, delete all data."},
        {"name": "PostgreSQL Connection", "regex": r"(postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s\"']+)", "severity": "critical", "method": "PostgreSQL connection string with password. Full database access."},
        {"name": "MySQL Connection", "regex": r"(mysql:\/\/[^:]+:[^@]+@[^\s\"']+)", "severity": "critical", "method": "MySQL connection string with credentials. Full database access."},
        {"name": "Redis URL", "regex": r"(redis:\/\/:[^@]+@[^\s\"']+)", "severity": "high", "method": "Redis connection with password. Can read cached data, session tokens, and modify cache."},
        {"name": "Elasticsearch URL", "regex": r"(https?://[^:]+:[^@]+@[a-z0-9.-]+elastic[a-z.-]*\.(?:cloud|com|io)[^\s\"']*)", "severity": "high", "method": "Elasticsearch cluster URL with credentials. Full search index access."},
    ],

    "payment": [
        {"name": "Stripe Secret Key", "regex": r"\b(sk_live_[a-zA-Z0-9]{24,})\b", "severity": "critical", "method": "Stripe live secret key. Can create charges, refunds, retrieve customer cards, and transfer funds. Direct financial access."},
        {"name": "Stripe Restricted Key", "regex": r"\b(rk_live_[a-zA-Z0-9]{24,})\b", "severity": "critical", "method": "Stripe restricted live key. Scoped access to specific Stripe operations - still dangerous."},
        {"name": "PayPal Client Secret", "regex": r"PAYPAL[_]?CLIENT[_]?SECRET\s*[=:]\s*['\"]?(EH[A-Za-z0-9_\-]{20,})['\"]?", "severity": "critical", "method": "PayPal API client secret. Can process payments, issue refunds, and access account balances."},
        {"name": "Square API Key", "regex": r"SQUARE[_]?API[_]?KEY\s*[=:]\s*['\"]?(sq0atp-[A-Za-z0-9_\-]{22})['\"]?", "severity": "critical", "method": "Square API access token. Can process payments, manage orders, and access merchant data."},
        {"name": "Razorpay Key Secret", "regex": r"RAZORPAY[_]?KEY[_]?SECRET\s*[=:]\s*['\"]?([A-Za-z0-9]{20,})['\"]?", "severity": "high", "method": "Razorpay API key secret. Can capture payments, issue refunds, and access transaction data."},
    ],

    "general": [
        {"name": "Generic API Key", "regex": r"(?:api[_]?key|api[_]?secret|secret[_]?key)\s*[=:]\s*['\"]([A-Za-z0-9+/=_\-]{16,64})['\"]", "severity": "medium", "method": "Generic API key or secret. Context-dependent - check surrounding code for what service it accesses."},
        {"name": "Bearer Token", "regex": r"(?:bearer|authorization)[\"']?\s*[:=]\s*[\"']?(Bearer\s+)?([A-Za-z0-9_\-\.]{20,})['\"]?", "severity": "medium", "method": "Bearer authorization token. Used for API authentication - can impersonate the token owner."},
        {"name": "JWT Token", "regex": r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b", "severity": "medium", "method": "JWT authentication token. Decode the payload to see user claims. Can impersonate the user until expiry."},
        {"name": "GitHub Token", "regex": r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", "severity": "high", "method": "GitHub personal access token. Can access private repos, create commits, and access GitHub API as the user."},
        {"name": "Google API Key", "regex": r"GOOGLE[_]?API[_]?KEY\s*[=:]\s*['\"]?(AIza[A-Za-z0-9_\-]{35})['\"]?", "severity": "medium", "method": "Google API key. Access to Google Cloud services - Maps, Translate, Vision, etc. depending on enabled APIs."},
        {"name": "Slack Token", "regex": r"\b(xox[bpors]-[A-Za-z0-9-]{10,})\b", "severity": "high", "method": "Slack API token. Can read channels, send messages, access files, and enumerate workspace members."},
        {"name": "OpenAI API Key", "regex": r"\b(sk-[A-Za-z0-9]{20,})\b", "severity": "high", "method": "OpenAI API key. Can use GPT models, DALL-E, and other OpenAI services. Costs billed to the key owner."},
        {"name": "Email:Password Combo", "regex": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[:\s]+([A-Za-z0-9!@#$%^&*()_+=\-]{6,})", "severity": "high", "method": "Email and password combination. Can be used for credential stuffing attacks on any service where the user reused this password."},
    ],
}

# Dork queries for Google Dorking scanner
DORK_QUERIES = {
    "database": [
        'filetype:env "DATABASE_URL"',
        'filetype:env "MONGO_URI"',
        'filetype:env "MONGODB_URI"',
        'filetype:env "REDIS_URL"',
        'filetype:env "POSTGRES"',
        'filetype:env "MYSQL"',
        'intitle:"index of" ".env"',
        'filetype:sql "INSERT INTO" "password"',
        'filetype:sql "CREATE USER" "PASSWORD"',
    ],
    "crypto_exchange": [
        'filetype:env "BINANCE_API"',
        'filetype:env "COINBASE_API"',
        'filetype:env "KRAKEN_API"',
        'filetype:env "BYBIT_API"',
        'filetype:env "KUCOIN_API"',
        'filetype:env "FTX_API"',
        'filetype:json "binance" "api_key" "secret"',
        'filetype:json "kraken" "apiKey" "secret"',
        'filetype:env "BITFINEX_API"',
    ],
    "crypto_wallet": [
        'filetype:json "private_key"',
        'ext:txt "wallet.dat"',
        'filetype:env "MNEMONIC"',
        'filetype:env "SEED_PHRASE"',
        'filetype:txt "5K" "Bitcoin"',
        'filetype:txt "litecoin" "private" "key"',
        'ext:json "keystore" "encrypted"',
    ],
    "server": [
        'filetype:env "SSH_PRIVATE_KEY"',
        'filetype:pem "PRIVATE KEY"',
        'filetype:env "AWS_SECRET_ACCESS_KEY"',
        'filetype:env "AWS_ACCESS_KEY_ID"',
        'filetype:env "DIGITALOCEAN_ACCESS_TOKEN"',
        'filetype:env "GCP_SERVICE_ACCOUNT"',
        'filetype:json "type": "service_account"',
        'filetype:env "AZURE_STORAGE_KEY"',
        'filetype:env "HEROKU_API_KEY"',
    ],
    "social_media": [
        'filetype:env "FACEBOOK_ACCESS_TOKEN"',
        'filetype:env "TWITTER_BEARER_TOKEN"',
        'filetype:env "INSTAGRAM_ACCESS_TOKEN"',
        'filetype:env "DISCORD_BOT_TOKEN"',
        'filetype:env "TELEGRAM_BOT_TOKEN"',
        'filetype:env "SNAPCHAT_API_TOKEN"',
        'filetype:env "SNAPCHAT_CLIENT_SECRET"',
        'filetype:env "TIKTOK_ACCESS_TOKEN"',
        'filetype:env "LINKEDIN_ACCESS_TOKEN"',
        'filetype:env "REDDIT_API_SECRET"',
    ],
    "telco": [
        'filetype:env "TELSTRA_API"',
        'filetype:env "OPTUS_API"',
        'filetype:env "VODAFONE_API"',
        'filetype:env "TWILIO_AUTH_TOKEN"',
        'filetype:env "TWILIO_ACCOUNT_SID"',
    ],
    "payment": [
        'filetype:env "STRIPE_SECRET_KEY"',
        'filetype:env "PAYPAL_CLIENT_SECRET"',
        'filetype:env "SQUARE_API_KEY"',
        'filetype:env "RAZORPAY_KEY_SECRET"',
    ],
    "config": [
        'intitle:"index of" "config.php"',
        'intitle:"index of" "settings.py"',
        'intitle:"index of" "wp-config.php"',
        'intitle:"index of" "application.yml"',
        'intitle:"index of" "credentials"',
    ],
    "api_keys": [
        'filetype:json "api_key" "secret"',
        'filetype:yaml "api_key:" "secret:"',
        'filetype:env "API_SECRET"',
        'filetype:env "OPENAI_API_KEY"',
        'filetype:env "GITHUB_TOKEN"',
        'filetype:env "SLACK_TOKEN"',
    ],
}
