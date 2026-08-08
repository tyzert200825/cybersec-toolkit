import { createClientFromRequest } from "npm:@base44/sdk@0.8.31";

Deno.serve(async (req: Request) => {
  try {
    const base44 = createClientFromRequest(req);
    const db = base44.asServiceRole;
    const findings = await db.entities.SecretFinding.list({ limit: 500, sort: "-created_date" });

    const stats = {
      total: findings.length,
      verified: findings.filter((f: any) => f.verified === true).length,
      critical: findings.filter((f: any) => f.severity === "critical").length,
      high: findings.filter((f: any) => f.severity === "high").length,
      medium: findings.filter((f: any) => f.severity === "medium").length,
      byMethod: {
        oops_scanner: findings.filter((f: any) => f.scanMethod === "oops_scanner").length,
        code_dorker: findings.filter((f: any) => f.scanMethod === "code_dorker").length,
      },
      lastScan: findings.length > 0 ? findings[0].created_date : null,
    };

    return new Response(JSON.stringify({ findings, stats, scannedAt: new Date().toISOString() }), {
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      status: 500,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }
});