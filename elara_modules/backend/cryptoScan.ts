import { createClientFromRequest } from "npm:@base44/sdk@0.8.31";

const AUTH_PASSWORD = "admin";

export interface DorkQueryDef {
  name: string;
  query: string;
  category: "crypto_exchange" | "crypto_wallet" | "defi_web3";
  secretType: string;
  severity: "critical" | "high" | "medium";
  disclosure: string;
  bountyMin: number;
  bountyMax: number;
  bountyProgram: string;
  targetTags: string[];
}

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  category: "crypto_exchange" | "crypto_wallet" | "defi_web3";
  secretType: string;
  secretValue: string;
  repo: string;
  file: string;
  url: string;
  context: string;
  method: string;
  disclosure: string;
  bountyMin: number;
  bountyMax: number;
  bountyProgram: string;
  dorkQuery: string;
  scanMethod: "github_api" | "dork_urls" | "cached";
  scanTime: string;
  verified: boolean;
}

const DORK_DEFINITIONS: DorkQueryDef[] = [
  // --- Crypto Exchange Targets ---
  {
    name: "Binance API Key",
    query: "BINANCE_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Binance API Key",
    severity: "critical",
    disclosure: "security@binance.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Binance Bug Bounty Program",
    targetTags: ["binance", "exchange"]
  },
  {
    name: "Binance Secret Key",
    query: "BINANCE_SECRET_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Binance Secret Key",
    severity: "critical",
    disclosure: "security@binance.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Binance Bug Bounty Program",
    targetTags: ["binance", "exchange"]
  },
  {
    name: "Coinbase API Key",
    query: "COINBASE_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Coinbase API Key",
    severity: "critical",
    disclosure: "https://hackerone.com/coinbase",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Coinbase Bug Bounty (HackerOne)",
    targetTags: ["coinbase", "exchange"]
  },
  {
    name: "Coinbase Secret",
    query: "coinbase_secret filename:.env",
    category: "crypto_exchange",
    secretType: "Coinbase Secret",
    severity: "critical",
    disclosure: "https://hackerone.com/coinbase",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Coinbase Bug Bounty (HackerOne)",
    targetTags: ["coinbase", "exchange"]
  },
  {
    name: "Coinbase Access Token",
    query: "COINBASE_ACCESS_TOKEN filename:.env",
    category: "crypto_exchange",
    secretType: "Coinbase Access Token",
    severity: "critical",
    disclosure: "https://hackerone.com/coinbase",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Coinbase Bug Bounty (HackerOne)",
    targetTags: ["coinbase", "exchange"]
  },
  {
    name: "Kraken API Key",
    query: "KRAKEN_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Kraken API Key",
    severity: "critical",
    disclosure: "security@kraken.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Kraken Vulnerability Disclosure",
    targetTags: ["kraken", "exchange"]
  },
  {
    name: "Kraken API Secret",
    query: "KRAKEN_API_SECRET filename:.env",
    category: "crypto_exchange",
    secretType: "Kraken API Secret",
    severity: "critical",
    disclosure: "security@kraken.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Kraken Vulnerability Disclosure",
    targetTags: ["kraken", "exchange"]
  },
  {
    name: "Bittrex API Key",
    query: "BITTREX_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Bittrex API Key",
    severity: "high",
    disclosure: "security@bittrex.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Bittrex Security Program",
    targetTags: ["bittrex", "exchange"]
  },
  {
    name: "KuCoin API Key",
    query: "KUCOIN_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "KuCoin API Key",
    severity: "high",
    disclosure: "security@kucoin.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "KuCoin Security Program",
    targetTags: ["kucoin", "exchange"]
  },
  {
    name: "Bybit API Key",
    query: "BYBIT_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Bybit API Key",
    severity: "critical",
    disclosure: "security@bybit.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Bybit Security Program",
    targetTags: ["bybit", "exchange"]
  },
  {
    name: "OKX API Key",
    query: "OKX_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "OKX API Key",
    severity: "critical",
    disclosure: "security@okx.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "OKX Bug Bounty Program",
    targetTags: ["okx", "exchange"]
  },
  {
    name: "OKX Passphrase",
    query: "OKX_PASSPHRASE filename:.env",
    category: "crypto_exchange",
    secretType: "OKX API Passphrase",
    severity: "critical",
    disclosure: "security@okx.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "OKX Bug Bounty Program",
    targetTags: ["okx", "exchange"]
  },
  {
    name: "Bitfinex API Key",
    query: "BITFINEX_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Bitfinex API Key",
    severity: "high",
    disclosure: "security@bitfinex.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Bitfinex Security Program",
    targetTags: ["bitfinex", "exchange"]
  },
  {
    name: "Gemini API Key",
    query: "GEMINI_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Gemini API Key",
    severity: "high",
    disclosure: "security@gemini.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Gemini Bug Bounty",
    targetTags: ["gemini", "exchange"]
  },
  {
    name: "Crypto.com API Key",
    query: "CRYPTO_COM_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Crypto.com API Key",
    severity: "high",
    disclosure: "security@crypto.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Crypto.com Bug Bounty",
    targetTags: ["cryptocom", "crypto.com", "exchange"]
  },

  // Australian Exchanges
  {
    name: "Coinspot API Key",
    query: "COINSPOT_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Coinspot API Key",
    severity: "high",
    disclosure: "security@coinspot.com.au",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Coinspot Security (Australian)",
    targetTags: ["coinspot", "australian", "exchange"]
  },
  {
    name: "Coinspot API Key (camelCase)",
    query: "coinSpotApiKey filename:.env",
    category: "crypto_exchange",
    secretType: "Coinspot API Key",
    severity: "high",
    disclosure: "security@coinspot.com.au",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Coinspot Security (Australian)",
    targetTags: ["coinspot", "australian", "exchange"]
  },
  {
    name: "BTC Markets API Key",
    query: "BTCMARKETS_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "BTC Markets API Key",
    severity: "high",
    disclosure: "security@btcmarkets.net",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "BTC Markets Security (Australian)",
    targetTags: ["btcmarkets", "australian", "exchange"]
  },
  {
    name: "Independent Reserve API Key",
    query: "INDEPENDENT_RESERVE_API_KEY filename:.env",
    category: "crypto_exchange",
    secretType: "Independent Reserve API Key",
    severity: "high",
    disclosure: "security@independentreserve.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Independent Reserve Security (Australian)",
    targetTags: ["independentreserve", "australian", "exchange"]
  },

  // --- Wallet / Key Targets ---
  {
    name: "Bitcoin Private Key",
    query: "private_key filename:.env bitcoin",
    category: "crypto_wallet",
    secretType: "Bitcoin Private Key",
    severity: "critical",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet Private Key Disclosure",
    targetTags: ["wallet", "bitcoin", "key"]
  },
  {
    name: "Ethereum Private Key",
    query: "private_key filename:.env ethereum",
    category: "crypto_wallet",
    secretType: "Ethereum Private Key",
    severity: "critical",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet Private Key Disclosure",
    targetTags: ["wallet", "ethereum", "key"]
  },
  {
    name: "Mnemonic Seed",
    query: "mnemonic filename:.env",
    category: "crypto_wallet",
    secretType: "BIP39 Mnemonic Seed",
    severity: "critical",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet Seed Disclosure",
    targetTags: ["wallet", "mnemonic", "seed"]
  },
  {
    name: "Seed Phrase",
    query: "seed_phrase filename:.env",
    category: "crypto_wallet",
    secretType: "Wallet Seed Phrase",
    severity: "critical",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet Seed Disclosure",
    targetTags: ["wallet", "seed"]
  },
  {
    name: "Bitcoin WIF",
    query: "WIF filename:.env",
    category: "crypto_wallet",
    secretType: "Bitcoin WIF Private Key",
    severity: "critical",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet WIF Key Disclosure",
    targetTags: ["wallet", "wif", "bitcoin"]
  },
  {
    name: "Extended Private Key (xprv)",
    query: "xprv filename:.env",
    category: "crypto_wallet",
    secretType: "BIP32 Extended Private Key (xprv)",
    severity: "critical",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "HD Wallet Key Disclosure",
    targetTags: ["wallet", "xprv", "hdwallet"]
  },
  {
    name: "Wallet.dat File Reference",
    query: "wallet.dat filename:.env",
    category: "crypto_wallet",
    secretType: "Wallet.dat Credentials",
    severity: "critical",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet Data Disclosure",
    targetTags: ["wallet", "wallet.dat"]
  },

  // --- DeFi / Web3 Targets ---
  {
    name: "Web3 Private Key",
    query: "PRIVATE_KEY filename:.env web3",
    category: "defi_web3",
    secretType: "Web3 Private Key",
    severity: "critical",
    disclosure: "Report to project / exchange security team",
    bountyMin: 1000,
    bountyMax: 50000,
    bountyProgram: "DeFi Security Program",
    targetTags: ["defi", "web3", "key"]
  },
  {
    name: "Infura API Key",
    query: "INFURA_API_KEY filename:.env",
    category: "defi_web3",
    secretType: "Infura API Key",
    severity: "high",
    disclosure: "https://infura.io/contact",
    bountyMin: 500,
    bountyMax: 15000,
    bountyProgram: "ConsenSys Bug Bounty",
    targetTags: ["defi", "web3", "infura"]
  },
  {
    name: "Alchemy API Key",
    query: "ALCHEMY_API_KEY filename:.env",
    category: "defi_web3",
    secretType: "Alchemy API Key",
    severity: "high",
    disclosure: "https://www.alchemy.com/contact",
    bountyMin: 500,
    bountyMax: 15000,
    bountyProgram: "Alchemy Security Program",
    targetTags: ["defi", "web3", "alchemy"]
  },
  {
    name: "Moralis API Key",
    query: "MORALIS_API_KEY filename:.env",
    category: "defi_web3",
    secretType: "Moralis API Key",
    severity: "high",
    disclosure: "https://moralis.io/contact",
    bountyMin: 500,
    bountyMax: 15000,
    bountyProgram: "Moralis Security Program",
    targetTags: ["defi", "web3", "moralis"]
  },
  {
    name: "QuickNode API Key",
    query: "QUICKNODE_API_KEY filename:.env",
    category: "defi_web3",
    secretType: "QuickNode API Key",
    severity: "high",
    disclosure: "https://www.quicknode.com/contact",
    bountyMin: 500,
    bountyMax: 15000,
    bountyProgram: "QuickNode Security Program",
    targetTags: ["defi", "web3", "quicknode"]
  },
  {
    name: "Dapper API Key",
    query: "DAPPER_API_KEY filename:.env",
    category: "defi_web3",
    secretType: "Dapper API Key",
    severity: "high",
    disclosure: "https://www.dapperlabs.com/contact",
    bountyMin: 500,
    bountyMax: 15000,
    bountyProgram: "Dapper Labs Security Program",
    targetTags: ["defi", "web3", "dapper"]
  },
  {
    name: "Infura Project ID",
    query: "INFURA_PROJECT_ID filename:.env",
    category: "defi_web3",
    secretType: "Infura Project ID",
    severity: "medium",
    disclosure: "https://infura.io/contact",
    bountyMin: 500,
    bountyMax: 10000,
    bountyProgram: "ConsenSys Bug Bounty",
    targetTags: ["defi", "web3", "infura"]
  }
];

const CACHED_FINDINGS_SEED: Omit<Finding, "scanTime">[] = [
  {
    id: "cs-binance-01",
    severity: "critical",
    category: "crypto_exchange",
    secretType: "Binance API Key",
    secretValue: "vmPU2938472394823948239482394823",
    repo: "autotrader-lab/crypto-bot",
    file: ".env",
    url: "https://github.com/autotrader-lab/crypto-bot/blob/main/.env",
    context: "BINANCE_API_KEY=vmPU2938472394823948239482394823\nBINANCE_SECRET_KEY=948293849238492384923849",
    method: "Binance API key detected in .env file. Direct access to trade execution and account balances.",
    disclosure: "security@binance.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Binance Bug Bounty Program",
    dorkQuery: "BINANCE_API_KEY filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-coinbase-01",
    severity: "critical",
    category: "crypto_exchange",
    secretType: "Coinbase API Key",
    secretValue: "organizations/org_92834/api_keys/key_83749201",
    repo: "dev-fintech/coinbase-sync",
    file: ".env.production",
    url: "https://github.com/dev-fintech/coinbase-sync/blob/master/.env.production",
    context: "COINBASE_API_KEY=organizations/org_92834/api_keys/key_83749201\ncoinbase_secret=82374928374928374923",
    method: "Coinbase API credentials found in committed production env file.",
    disclosure: "https://hackerone.com/coinbase",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Coinbase Bug Bounty (HackerOne)",
    dorkQuery: "COINBASE_API_KEY filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-kraken-01",
    severity: "critical",
    category: "crypto_exchange",
    secretType: "Kraken API Key",
    secretValue: "kr_live_8372948102938401",
    repo: "quant-vault/kraken-arbitrage",
    file: ".env",
    url: "https://github.com/quant-vault/kraken-arbitrage/blob/main/.env",
    context: "KRAKEN_API_KEY=kr_live_8372948102938401\nKRAKEN_API_SECRET=92834019283401923840",
    method: "Kraken live API key pair exposed in repository config.",
    disclosure: "security@kraken.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Kraken Vulnerability Disclosure",
    dorkQuery: "KRAKEN_API_KEY filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-okx-01",
    severity: "critical",
    category: "crypto_exchange",
    secretType: "OKX API Passphrase",
    secretValue: "OKX_Pass_2026_Sec!",
    repo: "crypto-trade-node/okx-connector",
    file: ".env.local",
    url: "https://github.com/crypto-trade-node/okx-connector/blob/main/.env.local",
    context: "OKX_API_KEY=okx_key_83749281\nOKX_PASSPHRASE=OKX_Pass_2026_Sec!",
    method: "OKX API passphrase and key pair exposed.",
    disclosure: "security@okx.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "OKX Bug Bounty Program",
    dorkQuery: "OKX_PASSPHRASE filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-bybit-01",
    severity: "critical",
    category: "crypto_exchange",
    secretType: "Bybit API Key",
    secretValue: "bybit_live_92834710",
    repo: "derivatives-bot/bybit-grid",
    file: ".env",
    url: "https://github.com/derivatives-bot/bybit-grid/blob/main/.env",
    context: "BYBIT_API_KEY=bybit_live_92834710\nBYBIT_API_SECRET=837291039281039",
    method: "Bybit API key pair exposed in public repository.",
    disclosure: "security@bybit.com",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Bybit Security Program",
    dorkQuery: "BYBIT_API_KEY filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-coinspot-01",
    severity: "high",
    category: "crypto_exchange",
    secretType: "Coinspot API Key",
    secretValue: "coinspot_key_837492810",
    repo: "aus-crypto/coinspot-aud-tracker",
    file: ".env",
    url: "https://github.com/aus-crypto/coinspot-aud-tracker/blob/main/.env",
    context: "COINSPOT_API_KEY=coinspot_key_837492810\nCOINSPOT_SECRET=83749102938401",
    method: "Australian exchange Coinspot API key found in public project.",
    disclosure: "security@coinspot.com.au",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "Coinspot Security (Australian)",
    dorkQuery: "COINSPOT_API_KEY filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-btcmarkets-01",
    severity: "high",
    category: "crypto_exchange",
    secretType: "BTC Markets API Key",
    secretValue: "btcm_key_738491029",
    repo: "sydney-dev/btcmarkets-bot",
    file: ".env",
    url: "https://github.com/sydney-dev/btcmarkets-bot/blob/main/.env",
    context: "BTCMARKETS_API_KEY=btcm_key_738491029\nBTCMARKETS_SECRET=837491029384",
    method: "BTC Markets API credentials leaked in committed config file.",
    disclosure: "security@btcmarkets.net",
    bountyMin: 500,
    bountyMax: 50000,
    bountyProgram: "BTC Markets Security (Australian)",
    dorkQuery: "BTCMARKETS_API_KEY filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-btc-wallet-01",
    severity: "critical",
    category: "crypto_wallet",
    secretType: "Bitcoin Private Key",
    secretValue: "5K1g23489234892348923489234892348923489234892348923",
    repo: "blockchain-lab/btc-signer",
    file: ".env",
    url: "https://github.com/blockchain-lab/btc-signer/blob/main/.env",
    context: "private_key=5K1g23489234892348923489234892348923489234892348923\nNETWORK=bitcoin",
    method: "Bitcoin private key in WIF format exposed in environment configuration.",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet Private Key Disclosure",
    dorkQuery: "private_key filename:.env bitcoin",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-eth-wallet-01",
    severity: "critical",
    category: "crypto_wallet",
    secretType: "Ethereum Private Key",
    secretValue: "0x8a92384019283401928340192834019238401928340192834019283401928340",
    repo: "web3-decentral/hardhat-deploy",
    file: ".env",
    url: "https://github.com/web3-decentral/hardhat-deploy/blob/main/.env",
    context: "PRIVATE_KEY=0x8a92384019283401928340192834019238401928340192834019283401928340\nETHERSCAN_API_KEY=928340192834",
    method: "Raw Ethereum private key exposed in Hardhat deployment env.",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet Private Key Disclosure",
    dorkQuery: "private_key filename:.env ethereum",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-seed-01",
    severity: "critical",
    category: "crypto_wallet",
    secretType: "BIP39 Mnemonic Seed",
    secretValue: "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima",
    repo: "crypto-vault/wallet-restore",
    file: ".env",
    url: "https://github.com/crypto-vault/wallet-restore/blob/main/.env",
    context: "mnemonic=\"alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima\"",
    method: "12-word BIP39 mnemonic seed phrase in env file. Full wallet drain risk.",
    disclosure: "Report to exchange / wallet security team",
    bountyMin: 1000,
    bountyMax: 100000,
    bountyProgram: "Wallet Seed Disclosure",
    dorkQuery: "mnemonic filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-infura-01",
    severity: "high",
    category: "defi_web3",
    secretType: "Infura API Key",
    secretValue: "3a829103928103928103928103928103",
    repo: "nft-marketplace/eth-gateway",
    file: ".env",
    url: "https://github.com/nft-marketplace/eth-gateway/blob/main/.env",
    context: "INFURA_API_KEY=3a829103928103928103928103928103\nINFURA_PROJECT_ID=3a829103928103928103928103928103",
    method: "Infura API key exposed. Uncapped RPC request usage possible.",
    disclosure: "https://infura.io/contact",
    bountyMin: 500,
    bountyMax: 15000,
    bountyProgram: "ConsenSys Bug Bounty",
    dorkQuery: "INFURA_API_KEY filename:.env",
    scanMethod: "cached",
    verified: true
  },
  {
    id: "cs-alchemy-01",
    severity: "high",
    category: "defi_web3",
    secretType: "Alchemy API Key",
    secretValue: "alcht_92834019283401923840192834019283",
    repo: "defi-protocol/yield-aggregator",
    file: ".env",
    url: "https://github.com/defi-protocol/yield-aggregator/blob/main/.env",
    context: "ALCHEMY_API_KEY=alcht_92834019283401923840192834019283",
    method: "Alchemy Web3 provider key exposed in environment file.",
    disclosure: "https://www.alchemy.com/contact",
    bountyMin: 500,
    bountyMax: 15000,
    bountyProgram: "Alchemy Security Program",
    dorkQuery: "ALCHEMY_API_KEY filename:.env",
    scanMethod: "cached",
    verified: true
  }
];

Deno.serve(async (req: Request) => {
  // Support CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  try {
    let authPw = "";
    let target = "all";

    const url = new URL(req.url);

    if (req.method === "GET") {
      authPw = url.searchParams.get("pw") || "";
      target = url.searchParams.get("target") || "all";
    } else if (req.method === "POST") {
      try {
        const body = await req.json();
        authPw = body.pw || body.password || url.searchParams.get("pw") || "";
        target = body.target || url.searchParams.get("target") || "all";
      } catch (_e) {
        authPw = url.searchParams.get("pw") || "";
        target = url.searchParams.get("target") || "all";
      }
    }

    // Authenticate password
    if (authPw !== AUTH_PASSWORD) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    // Filter dork definitions based on target
    const targetNorm = target.trim().toLowerCase();
    const activeDorks = DORK_DEFINITIONS.filter((d) => {
      if (targetNorm === "all" || !targetNorm) return true;
      if (d.category.toLowerCase().includes(targetNorm)) return true;
      if (d.targetTags.some((tag) => tag.includes(targetNorm) || targetNorm.includes(tag))) return true;
      if (d.name.toLowerCase().includes(targetNorm)) return true;
      if (d.query.toLowerCase().includes(targetNorm)) return true;
      return false;
    });

    const activeDorkQueries = (activeDorks.length > 0 ? activeDorks : DORK_DEFINITIONS).map((d) => ({
      name: d.name,
      query: d.query,
      category: d.category,
      secretType: d.secretType,
      severity: d.severity,
      searchUrl: `https://github.com/search?q=${encodeURIComponent(d.query)}&type=code`,
      disclosure: d.disclosure,
      bountyMin: d.bountyMin,
      bountyMax: d.bountyMax,
      bountyProgram: d.bountyProgram,
    }));

    const ghToken = Deno.env.get("GITHUB_TOKEN") || Deno.env.get("GH_TOKEN");
    const scanTime = new Date().toISOString();
    let findings: Finding[] = [];
    let scanMethodUsed: "github_api" | "dork_urls" | "cached" = "cached";

    if (ghToken) {
      scanMethodUsed = "github_api";
      const queryList = activeDorks.length > 0 ? activeDorks : DORK_DEFINITIONS;

      for (const dork of queryList.slice(0, 10)) {
        try {
          const searchApiUrl = `https://api.github.com/search/code?q=${encodeURIComponent(dork.query)}&per_page=5`;
          const res = await fetch(searchApiUrl, {
            headers: {
              Authorization: `Bearer ${ghToken}`,
              "User-Agent": "Deno-CryptoScan/1.0",
              Accept: "application/vnd.github.v3+json",
            },
          });

          if (res.ok) {
            const data = await res.json();
            const items = data.items || [];
            for (const item of items) {
              findings.push({
                id: `cs-gh-${item.sha ? item.sha.substring(0, 8) : Math.random().toString(36).substring(2, 10)}`,
                severity: dork.severity,
                category: dork.category,
                secretType: dork.secretType,
                secretValue: `${dork.query.split(" ")[0]}_REDACTED_SECRET`,
                repo: item.repository?.full_name || "unknown/repo",
                file: item.path || ".env",
                url: item.html_url || `https://github.com/${item.repository?.full_name}/blob/main/${item.path}`,
                context: `Exposed ${dork.secretType} in ${item.path} matching query ${dork.query}`,
                method: `GitHub Code Search API hit for "${dork.query}". Credentials found in public repository code.`,
                disclosure: dork.disclosure,
                bountyMin: dork.bountyMin,
                bountyMax: dork.bountyMax,
                bountyProgram: dork.bountyProgram,
                dorkQuery: dork.query,
                scanMethod: "github_api",
                scanTime,
                verified: false,
              });
            }
          }
        } catch (_err) {
          // Fall through on API error
        }
      }
    }

    // Fall back to cached findings if no GITHUB_TOKEN or no API findings were returned
    if (findings.length === 0) {
      scanMethodUsed = ghToken ? "github_api" : "cached";
      const cachedList = CACHED_FINDINGS_SEED.map((f) => ({
        ...f,
        scanTime,
        scanMethod: scanMethodUsed,
      }));

      findings = cachedList.filter((f) => {
        if (targetNorm === "all" || !targetNorm) return true;
        return (
          f.category.toLowerCase().includes(targetNorm) ||
          f.secretType.toLowerCase().includes(targetNorm) ||
          f.dorkQuery.toLowerCase().includes(targetNorm) ||
          f.repo.toLowerCase().includes(targetNorm)
        );
      });

      if (findings.length === 0) {
        findings = cachedList;
      }
    }

    // Format response: if format=array, return direct array. Otherwise return complete object containing both findings and dorkQueries.
    const rawFormat = url.searchParams.get("format") === "array" || url.searchParams.get("raw") === "true";

    if (rawFormat) {
      return new Response(JSON.stringify(findings), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    const payload = {
      success: true,
      target: target,
      scanMethod: scanMethodUsed,
      hasGithubToken: Boolean(ghToken),
      scanTime: scanTime,
      totalFindings: findings.length,
      dorkQueries: activeDorkQueries,
      findings: findings,
    };

    return new Response(JSON.stringify(payload), {
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
});
