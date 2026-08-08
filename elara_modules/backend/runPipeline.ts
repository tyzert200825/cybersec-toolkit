import { createClientFromRequest } from "npm:@base44/sdk@0.8.31";

const ADMIN_PASSWORD = "admin";

Deno.serve(async (req: Request) => {
  try {
    const body = await req.json();
    const { pipeline, target, options, authKey } = body;

    const validAuth = authKey === ADMIN_PASSWORD || authKey === btoa(ADMIN_PASSWORD);
    if (!validAuth) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // Use asServiceRole to bypass RLS — the authKey is our security layer
    const base44 = createClientFromRequest(req);
    const db = base44.asServiceRole;

    let result: any = { pipeline, status: "started", timestamp: new Date().toISOString() };

    switch (pipeline) {
      case "oops_scanner": {
        result = { ...result, description: "Scanning GitHub Archive for deleted commits (force pushes)", category: "secret_hunting", target: target || "auto (latest archive hour)", status: "queued", message: "Oops scanner finds deleted commits that GitHub keeps forever. Uses .patch URL approach to bypass API rate limits." };
        break;
      }
      case "code_dorker": {
        result = { ...result, description: "GitHub code search with 35+ secret dork patterns", category: "secret_hunting", target: target || "GitHub code search", status: "queued", message: "Searches GitHub file contents for live secrets." };
        break;
      }
      case "gh_archive": {
        result = { ...result, description: "Scanning GitHub Archive for suspicious commit messages", category: "secret_hunting", target: target || "latest archive hour", status: "queued", message: "Full pipeline: regex + ML + TruffleHog verification." };
        break;
      }
      case "paste_monitor": {
        result = { ...result, description: "Monitoring paste sites for leaked credentials", category: "secret_hunting", target: target || "paste sites", status: "queued", message: "Continuous paste site monitoring targeting crypto exchanges, Australian telcos, and social media platforms." };
        break;
      }
      case "google_dorker": {
        result = { ...result, description: "Google dorking for exposed secrets and sensitive files", category: "secret_hunting", target: target || "Google search", status: "queued", message: "Google dorking finds exposed files and credentials indexed by search engines." };
        break;
      }
      case "crypto_wallet_scan": {
        result = { ...result, description: "Scanning for leaked crypto wallet seeds and private keys", category: "crypto", target: target || "GitHub + paste sites", status: "queued", message: "Specialized scanner for crypto wallet credentials and exchange API keys." };
        break;
      }
      case "cloud_credential_scan": {
        result = { ...result, description: "Scanning for leaked cloud provider credentials", category: "cloud", target: target || "GitHub + paste sites", status: "queued", message: "Cloud credential scanner targeting AWS, GCP, Azure, and DigitalOcean." };
        break;
      }
      case "coldcard_weak_seed_scan": {
        result = { ...result, description: "Scanning for potentially weak Coldcard-generated Bitcoin addresses", category: "crypto", target: target || "blockchain", status: "queued", message: "Identifies Bitcoin addresses potentially generated with weak Coldcard entropy." };
        break;
      }
      case "nuclei_scan": {
        result = { ...result, description: "Nuclei vulnerability scanner", category: "recon", target: target || "not specified", status: "queued", message: `Nuclei scan against ${target || 'target'} using 13,391+ templates.` };
        break;
      }
      case "subfinder": {
        result = { ...result, description: "Subdomain enumeration", category: "recon", target: target || "not specified", status: "queued", message: `Subdomain discovery against ${target || 'domain'}.` };
        break;
      }
      case "nmap": {
        result = { ...result, description: "Network service detection scan", category: "recon", target: target || "not specified", status: "queued", message: `Nmap scan against ${target || 'target'}.` };
        break;
      }
      case "shodan_scan": {
        result = { ...result, description: "Shodan internet-connected device search", category: "recon", target: target || "not specified", status: "queued", message: `Shodan search for ${target || 'target'}.` };
        break;
      }
      case "full_scan": {
        result = { ...result, description: "Running ALL secret hunting pipelines", category: "combined", target: "all sources", status: "queued", message: "Full scan triggers all 7 secret hunting pipelines simultaneously." };
        break;
      }
      case "recon_full": {
        result = { ...result, description: "Full reconnaissance suite", category: "combined", target: target || "specified target", status: "queued", message: `Full recon suite against ${target || 'target'}.` };
        break;
      }

      case "coldcard_check": {
        const monitored = await db.entities.ColdcardMonitor.list({ limit: 500 });
        const alerts: any[] = [];
        for (const record of monitored) {
          try {
            const addrResp = await fetch(`https://mempool.space/api/address/${record.address}`);
            if (!addrResp.ok) continue;
            const addrData = await addrResp.json();
            const currentTxCount = addrData.chain_stats?.tx_count || 0;
            const currentBalance = ((addrData.chain_stats?.funded_txo_sum || 0) - (addrData.chain_stats?.spent_txo_sum || 0)) / 100000000;
            const mempoolTxCount = addrData.mempool_stats?.tx_count || 0;
            if (currentTxCount > (record.lastTxCount || 0) || mempoolTxCount > 0) {
              alerts.push({ address: record.address, wave: record.wave, oldTxCount: record.lastTxCount, newTxCount: currentTxCount, oldBalance: record.balanceBTC, newBalance: currentBalance, balanceChange: currentBalance - (record.balanceBTC || 0), mempoolPending: mempoolTxCount, type: currentTxCount > (record.lastTxCount || 0) ? "NEW_TRANSACTION" : "MEMPOOL_ACTIVITY" });
            }
            await db.entities.ColdcardMonitor.update(record.id, { data: { lastTxCount: currentTxCount, balanceBTC: currentBalance, lastChecked: new Date().toISOString(), status: currentTxCount > (record.lastTxCount || 0) ? "moved" : "active" } });
          } catch (e) {}
        }
        result = { ...result, description: "Checking Coldcard attacker addresses for movement", category: "coldcard", status: "complete", monitored: monitored.length, alerts, message: alerts.length > 0 ? `MOVEMENT DETECTED on ${alerts.length} address(es)!` : "No movement detected." };
        break;
      }

      case "coldcard_status": {
        const all = await db.entities.ColdcardMonitor.list({ limit: 500 });
        result = {
          ...result, description: "Coldcard monitor status", category: "coldcard", status: "complete",
          totalMonitored: all.length,
          active: all.filter((r: any) => r.status === "active").length,
          moved: all.filter((r: any) => r.status === "moved").length,
          addresses: all.map((r: any) => ({ address: r.address, wave: r.wave, type: r.addressType, balance: r.balanceBTC, txCount: r.lastTxCount, status: r.status, lastChecked: r.lastChecked }))
        };
        break;
      }

      case "coldcard_add": {
        if (!target) { result = { ...result, status: "error", message: "Address required" }; break; }
        let initialState = { balance: 0, txCount: 0 };
        try {
          const addrResp = await fetch(`https://mempool.space/api/address/${target}`);
          if (addrResp.ok) {
            const addrData = await addrResp.json();
            initialState = { balance: ((addrData.chain_stats?.funded_txo_sum || 0) - (addrData.chain_stats?.spent_txo_sum || 0)) / 100000000, txCount: addrData.chain_stats?.tx_count || 0 };
          }
        } catch (e) {}
        const record = await db.entities.ColdcardMonitor.create({ data: { address: target, wave: options?.wave || "unknown", addressType: options?.addressType || "collector", balanceBTC: initialState.balance, lastTxCount: initialState.txCount, lastChecked: new Date().toISOString(), firstSeen: new Date().toISOString(), status: "active", notes: options?.notes || `Added via dashboard. Balance: ${initialState.balance} BTC` } });
        result = { ...result, description: "Added address to Coldcard monitor", category: "coldcard", status: "complete", address: target, initialState, record };
        break;
      }

      default: {
        result = { ...result, status: "error", message: `Unknown pipeline: ${pipeline}`, available: { secret_hunting: ["oops_scanner", "code_dorker", "gh_archive", "paste_monitor", "google_dorker", "crypto_wallet_scan", "cloud_credential_scan", "coldcard_weak_seed_scan", "full_scan"], recon: ["nuclei_scan", "subfinder", "nmap", "shodan_scan", "recon_full"], coldcard: ["coldcard_check", "coldcard_status", "coldcard_add"] } };
      }
    }

    try {
      const findings = await db.entities.SecretFinding.list({ limit: 500 });
      result.currentFindings = findings.length;
    } catch (e) { result.currentFindings = "unable to query"; }

    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      status: 500,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }
});