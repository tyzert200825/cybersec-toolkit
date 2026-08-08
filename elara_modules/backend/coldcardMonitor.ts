import { createClientFromRequest } from "npm:@base44/sdk@0.8.31";

const MEMPOOL_API = "https://mempool.space/api";

// Known attacker addresses from Chainalysis/Galaxy Research tracking
// Wave 1 consolidation: 562 BTC into single address (bc1qnk... prefix)
// Wave 2: shared collector addresses
// Wave 3: individual P2WSH addresses (4,585 total)
const KNOWN_ATTACKER_ADDRESSES = [
  // Wave 1 consolidation address - 562 BTC
  { address: "bc1qnk", wave: "wave1", addressType: "consolidation", notes: "Wave 1 consolidation - 562 BTC consolidated here. Partial address - needs full bc1 from on-chain analysis." },
];

Deno.serve(async (req: Request) => {
  try {
    const body = await req.json();
    const { action, address, authKey } = body;

    const ADMIN_PASSWORD = "Fuckyou25.!";
    const validAuth = authKey === ADMIN_PASSWORD || authKey === btoa(ADMIN_PASSWORD);
    
    if (!validAuth) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    const base44 = createClientFromRequest(req);

    // ACTION: Add a new address to monitor
    if (action === "addAddress") {
      if (!address) {
        return new Response(JSON.stringify({ error: "address required" }), {
          status: 400,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }

      // Check if address already monitored
      const existing = await base44.entities.ColdcardMonitor.list({
        filter: { address: address }
      });

      if (existing.length > 0) {
        return new Response(JSON.stringify({ 
          success: false, 
          message: "Address already being monitored",
          record: existing[0]
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }

      // Fetch initial state from mempool.space
      let initialState = { balance: 0, txCount: 0, funded: false };
      try {
        const addrResp = await fetch(`${MEMPOOL_API}/address/${address}`);
        if (addrResp.ok) {
          const addrData = await addrResp.json();
          initialState = {
            balance: (addrData.chain_stats?.funded_txo_sum || 0) - (addrData.chain_stats?.spent_txo_sum || 0),
            txCount: addrData.chain_stats?.tx_count || 0,
            funded: (addrData.chain_stats?.funded_txo_sum || 0) > 0
          };
          // Convert satoshis to BTC
          initialState.balance = initialState.balance / 100000000;
        }
      } catch (e) {
        // mempool.space might be unavailable
      }

      // Also fetch recent transactions
      let recentTxs: any[] = [];
      try {
        const txResp = await fetch(`${MEMPOOL_API}/address/${address}/txs`);
        if (txResp.ok) {
          recentTxs = await txResp.json();
        }
      } catch (e) {}

      const record = await base44.entities.ColdcardMonitor.create({
        data: {
          address: address,
          wave: body.wave || "unknown",
          addressType: body.addressType || "collector",
          balanceBTC: initialState.balance,
          lastTxCount: initialState.txCount,
          lastChecked: new Date().toISOString(),
          firstSeen: new Date().toISOString(),
          status: "active",
          notes: body.notes || `Added for monitoring. Initial balance: ${initialState.balance} BTC, ${initialState.txCount} txs.`
        }
      });

      return new Response(JSON.stringify({ 
        success: true, 
        message: "Address added to monitoring",
        address: address,
        initialState: initialState,
        recentTransactions: recentTxs.slice(0, 5).map((tx: any) => ({
          txid: tx.txid,
          value: (tx.vout?.reduce((s: number, v: any) => s + (v.value || 0), 0) || 0) / 100000000,
          confirmed: tx.status?.confirmed,
          blockHeight: tx.status?.block_height,
          time: tx.status?.block_time
        })),
        record: record
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // ACTION: Check all monitored addresses for movement
    if (action === "checkAll") {
      const monitored = await base44.entities.ColdcardMonitor.list({
        filter: { status: "active" },
        limit: 500
      });

      const alerts: any[] = [];
      const updates: any[] = [];

      for (const record of monitored) {
        try {
          const addrResp = await fetch(`${MEMPOOL_API}/address/${record.address}`);
          if (!addrResp.ok) continue;
          
          const addrData = await addrResp.json();
          const currentTxCount = addrData.chain_stats?.tx_count || 0;
          const currentBalance = ((addrData.chain_stats?.funded_txo_sum || 0) - (addrData.chain_stats?.spent_txo_sum || 0)) / 100000000;
          const mempoolTxCount = addrData.mempool_stats?.tx_count || 0;

          let status = "active";
          let alert = null;

          // Check for new transactions
          if (currentTxCount > record.lastTxCount) {
            // Fetch the new transactions
            const txResp = await fetch(`${MEMPOOL_API}/address/${record.address}/txs`);
            let newTxs: any[] = [];
            if (txResp.ok) {
              const allTxs = await txResp.json();
              newTxs = allTxs.slice(0, currentTxCount - record.lastTxCount);
            }

            status = "moved";
            alert = {
              type: "NEW_TRANSACTION",
              address: record.address,
              wave: record.wave,
              oldTxCount: record.lastTxCount,
              newTxCount: currentTxCount,
              newTransactions: currentTxCount - record.lastTxCount,
              oldBalance: record.balanceBTC,
              newBalance: currentBalance,
              balanceChange: currentBalance - record.balanceBTC,
              mempoolPending: mempoolTxCount,
              details: newTxs.slice(0, 3).map((tx: any) => ({
                txid: tx.txid,
                value: (tx.vout?.reduce((s: number, v: any) => s + (v.value || 0), 0) || 0) / 100000000,
                confirmed: tx.status?.confirmed,
                blockHeight: tx.status?.block_height,
                time: tx.status?.block_time
              }))
            };
            alerts.push(alert);
          }

          // Check for mempool activity (pending txs)
          if (mempoolTxCount > 0 && currentTxCount === record.lastTxCount) {
            alert = {
              type: "MEMPOOL_ACTIVITY",
              address: record.address,
              wave: record.wave,
              pendingTxs: mempoolTxCount,
              message: "Pending transaction detected in mempool"
            };
            alerts.push(alert);
          }

          // Update the record
          await base44.entities.ColdcardMonitor.update(record.id, {
            data: {
              lastTxCount: currentTxCount,
              balanceBTC: currentBalance,
              lastChecked: new Date().toISOString(),
              status: status
            }
          });

          updates.push({
            address: record.address,
            txCount: currentTxCount,
            balance: currentBalance,
            status: status
          });

        } catch (e) {
          updates.push({
            address: record.address,
            error: (e as Error).message
          });
        }
      }

      return new Response(JSON.stringify({
        success: true,
        checked: monitored.length,
        alerts: alerts,
        updates: updates,
        timestamp: new Date().toISOString()
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // ACTION: Get status of all monitored addresses
    if (action === "getStatus") {
      const all = await base44.entities.ColdcardMonitor.list({ limit: 500 });
      return new Response(JSON.stringify({
        success: true,
        totalMonitored: all.length,
        active: all.filter((r: any) => r.status === "active").length,
        moved: all.filter((r: any) => r.status === "moved").length,
        addresses: all.map((r: any) => ({
          address: r.address,
          wave: r.wave,
          type: r.addressType,
          balance: r.balanceBTC,
          txCount: r.lastTxCount,
          status: r.status,
          lastChecked: r.lastChecked
        }))
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // ACTION: Remove an address from monitoring
    if (action === "removeAddress") {
      if (!address) {
        return new Response(JSON.stringify({ error: "address required" }), {
          status: 400,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }

      const existing = await base44.entities.ColdcardMonitor.list({
        filter: { address: address }
      });

      if (existing.length === 0) {
        return new Response(JSON.stringify({ error: "Address not found in monitoring" }), {
          status: 404,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }

      await base44.entities.ColdcardMonitor.delete(existing[0].id);
      return new Response(JSON.stringify({ 
        success: true, 
        message: "Address removed from monitoring" 
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    return new Response(JSON.stringify({ 
      error: "Unknown action",
      available: ["addAddress", "checkAll", "getStatus", "removeAddress"]
    }), {
      status: 400,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      status: 500,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }
});