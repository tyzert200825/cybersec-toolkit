const PASSWORD = "admin";

const CORS_HEADERS = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

interface PortConfig {
  port: number;
  service: string;
}

const COMMON_PORTS: PortConfig[] = [
  { port: 21, service: "FTP" },
  { port: 22, service: "SSH" },
  { port: 23, service: "Telnet" },
  { port: 25, service: "SMTP" },
  { port: 53, service: "DNS" },
  { port: 80, service: "HTTP" },
  { port: 110, service: "POP3" },
  { port: 143, service: "IMAP" },
  { port: 443, service: "HTTPS" },
  { port: 445, service: "SMB" },
  { port: 993, service: "IMAPS" },
  { port: 995, service: "POP3S" },
  { port: 1433, service: "MSSQL" },
  { port: 1521, service: "Oracle DB" },
  { port: 3306, service: "MySQL" },
  { port: 3389, service: "RDP" },
  { port: 5432, service: "PostgreSQL" },
  { port: 5900, service: "VNC" },
  { port: 6379, service: "Redis" },
  { port: 8080, service: "HTTP-Alt" },
  { port: 8443, service: "HTTPS-Alt" },
  { port: 8888, service: "Jupyter/HTTP-Alt" },
  { port: 9090, service: "Prometheus/Cockpit" },
  { port: 27017, service: "MongoDB" },
];

const API_PATHS = [
  "/api",
  "/api/v1",
  "/api/v2",
  "/graphql",
  "/swagger",
  "/swagger-ui",
  "/api-docs",
  "/openapi.json",
  "/health",
  "/status",
  "/.env",
  "/.git/config",
  "/robots.txt",
  "/sitemap.xml",
  "/wp-admin",
  "/admin",
  "/login",
  "/actuator",
  "/actuator/health",
  "/debug",
  "/trace",
  "/metrics",
];

const SENSITIVE_PATHS = [
  "/.env",
  "/.git/config",
  "/actuator",
  "/actuator/health",
  "/debug",
  "/trace",
  "/metrics",
];

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  let targetUrl = "";
  let providedPw = "";

  try {
    const parsedUrl = new URL(req.url);
    if (req.method === "GET") {
      targetUrl = parsedUrl.searchParams.get("url") || "";
      providedPw = parsedUrl.searchParams.get("pw") || "";
    } else if (req.method === "POST") {
      try {
        const body = await req.json();
        targetUrl = body.url || parsedUrl.searchParams.get("url") || "";
        providedPw = body.pw || parsedUrl.searchParams.get("pw") || "";
      } catch (_e) {
        targetUrl = parsedUrl.searchParams.get("url") || "";
        providedPw = parsedUrl.searchParams.get("pw") || "";
      }
    } else {
      targetUrl = parsedUrl.searchParams.get("url") || "";
      providedPw = parsedUrl.searchParams.get("pw") || "";
    }
  } catch (_e) {
    return new Response(JSON.stringify({ error: "Invalid request URL" }), {
      status: 400,
      headers: CORS_HEADERS,
    });
  }

  if (!providedPw || providedPw !== PASSWORD) {
    return new Response(
      JSON.stringify({ error: "Unauthorized: Invalid or missing password" }),
      { status: 401, headers: CORS_HEADERS }
    );
  }

  if (!targetUrl) {
    return new Response(
      JSON.stringify({ error: "Missing required 'url' parameter" }),
      { status: 400, headers: CORS_HEADERS }
    );
  }

  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "https://" + targetUrl;
  }

  let parsedTarget: URL;
  try {
    parsedTarget = new URL(targetUrl);
  } catch (_e) {
    return new Response(
      JSON.stringify({ error: `Invalid target URL: ${targetUrl}` }),
      { status: 400, headers: CORS_HEADERS }
    );
  }

  const host = parsedTarget.hostname;
  const startTime = Date.now();

  // Fetch initial response with timeout
  let initialResponse: Response | null = null;
  let responseText = "";
  let fetchError = "";
  let responseHeaders: Headers = new Headers();
  let fetchTimeMs = 0;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const fetchStart = Date.now();
    initialResponse = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Base44SecurityScanner/1.0",
        "Accept": "*/*",
      },
    });
    fetchTimeMs = Date.now() - fetchStart;
    clearTimeout(timer);
    responseHeaders = initialResponse.headers;
    responseText = await initialResponse.text();
  } catch (err) {
    fetchError = (err as Error).message || String(err);
  }

  // --- Section 1: Security Headers Check ---
  let headersResult: any = { status: "failed", error: fetchError || null };
  try {
    const rawHeaders: Record<string, string> = {};
    responseHeaders.forEach((val, key) => {
      rawHeaders[key.toLowerCase()] = val;
    });

    const securityHeadersList = [
      {
        name: "Content-Security-Policy",
        key: "content-security-policy",
        desc: "Restricts resource loading to prevent XSS and injection attacks",
      },
      {
        name: "Strict-Transport-Security",
        key: "strict-transport-security",
        desc: "Enforces HTTPS connections (HSTS)",
      },
      {
        name: "X-Frame-Options",
        key: "x-frame-options",
        desc: "Protects against clickjacking",
      },
      {
        name: "X-Content-Type-Options",
        key: "x-content-type-options",
        desc: "Prevents MIME-type sniffing",
      },
      {
        name: "Referrer-Policy",
        key: "referrer-policy",
        desc: "Controls information sent in Referer header",
      },
      {
        name: "Permissions-Policy",
        key: "permissions-policy",
        desc: "Controls browser features and APIs",
      },
      {
        name: "X-XSS-Protection",
        key: "x-xss-protection",
        desc: "Legacy XSS filter control",
      },
    ];

    const checks = securityHeadersList.map((sh) => {
      const val = rawHeaders[sh.key] || null;
      return {
        header: sh.name,
        key: sh.key,
        present: val !== null,
        value: val,
        description: sh.desc,
        status: val !== null ? "pass" : "fail",
      };
    });

    const presentCount = checks.filter((c) => c.present).length;
    headersResult = {
      summary: `${presentCount}/${checks.length} security headers present`,
      missing_count: checks.length - presentCount,
      passed_count: presentCount,
      checks,
      all_headers: rawHeaders,
    };
  } catch (err) {
    headersResult = { status: "error", error: (err as Error).message };
  }

  // --- Section 2: SSL/TLS Info ---
  let sslResult: any = { valid: false };
  try {
    const isHttps = parsedTarget.protocol === "https:";
    if (!isHttps) {
      sslResult = {
        valid: false,
        protocol: "http",
        issuer: null,
        expiry_date: null,
        days_remaining: null,
        details: "Target URL does not use HTTPS",
      };
    } else if (fetchError && fetchError.toLowerCase().includes("certificate")) {
      sslResult = {
        valid: false,
        protocol: "https",
        issuer: null,
        expiry_date: null,
        days_remaining: null,
        details: `Certificate error: ${fetchError}`,
      };
    } else if (initialResponse) {
      let tlsDetails = "Valid SSL/TLS connection established";
      let connIssuer: string | null = null;
      let connValidTo: string | null = null;

      // Try Deno.connectTls if available
      try {
        if (typeof (Deno as any).connectTls === "function") {
          const conn = await (Deno as any).connectTls({
            hostname: host,
            port: parseInt(parsedTarget.port) || 443,
          });
          if (typeof conn.handshake === "function") {
            await conn.handshake();
          }
          conn.close();
          tlsDetails = "TLS handshake succeeded";
        }
      } catch (_e) {
        // Fallback info if Deno.connectTls throws or is restricted
      }

      sslResult = {
        valid: true,
        protocol: "https",
        issuer: connIssuer || "Verified CA (TLS OK)",
        expiry_date: connValidTo || "Active",
        days_remaining: null,
        details: tlsDetails,
      };
    } else {
      sslResult = {
        valid: false,
        protocol: "https",
        issuer: null,
        expiry_date: null,
        days_remaining: null,
        details: `Failed to establish connection: ${fetchError}`,
      };
    }
  } catch (err) {
    sslResult = { valid: false, error: (err as Error).message };
  }

  // --- Section 3: Tech Detection ---
  let techResult: any[] = [];
  try {
    const bodyLower = responseText.toLowerCase();
    const serverHeader = (responseHeaders.get("server") || "").toLowerCase();
    const poweredBy = (responseHeaders.get("x-powered-by") || "").toLowerCase();
    const setCookie = (responseHeaders.get("set-cookie") || "").toLowerCase();

    const techSignatures = [
      { name: "React", category: "Frontend Framework", pattern: /data-reactroot|_reactlistening|react-dom|react\.production/i, source: "html" },
      { name: "Vue.js", category: "Frontend Framework", pattern: /data-v-|vue\.js|vue\.min\.js|__nuxt__|v-cloak/i, source: "html" },
      { name: "Angular", category: "Frontend Framework", pattern: /ng-version|ng-app|ng-binding|angular\.js/i, source: "html" },
      { name: "Next.js", category: "Web Framework", pattern: /__next_data__|\/_next\//i, source: "html" },
      { name: "Nuxt.js", category: "Web Framework", pattern: /__nuxt__|\/_nuxt\//i, source: "html" },
      { name: "WordPress", category: "CMS", pattern: /wp-content|wp-includes|wp-json/i, source: "html" },
      { name: "Django", category: "Backend Framework", pattern: /csrfmiddlewaretoken|__admin__/i, source: "html" },
      { name: "Laravel", category: "Backend Framework", pattern: /laravel_session|x-srf-token/i, source: "cookie_html" },
      { name: "Bootstrap", category: "CSS Framework", pattern: /bootstrap\.css|bootstrap\.min\.js|bootstrap\.bundle/i, source: "html" },
      { name: "Tailwind CSS", category: "CSS Framework", pattern: /tailwind|tw-/i, source: "html" },
      { name: "jQuery", category: "JS Library", pattern: /jquery\.js|jquery\.min\.js|jquery v/i, source: "html" },
    ];

    for (const tech of techSignatures) {
      if (tech.pattern.test(bodyLower) || tech.pattern.test(setCookie)) {
        techResult.push({
          name: tech.name,
          category: tech.category,
          confidence: "high",
          evidence: `Matched pattern in ${tech.source}`,
        });
      }
    }

    // Header based tech
    if (serverHeader.includes("nginx")) techResult.push({ name: "Nginx", category: "Web Server", confidence: "high", evidence: "Server header: nginx" });
    if (serverHeader.includes("apache")) techResult.push({ name: "Apache", category: "Web Server", confidence: "high", evidence: "Server header: Apache" });
    if (serverHeader.includes("cloudflare")) techResult.push({ name: "Cloudflare", category: "CDN / Reverse Proxy", confidence: "high", evidence: "Server header: Cloudflare" });
    if (poweredBy.includes("express")) techResult.push({ name: "Express.js", category: "Backend Framework", confidence: "high", evidence: "X-Powered-By: Express" });
    if (poweredBy.includes("php")) techResult.push({ name: "PHP", category: "Programming Language", confidence: "high", evidence: `X-Powered-By: ${poweredBy}` });
    if (poweredBy.includes("asp.net")) techResult.push({ name: "ASP.NET", category: "Backend Framework", confidence: "high", evidence: "X-Powered-By: ASP.NET" });
    if (poweredBy.includes("wordpress")) techResult.push({ name: "WordPress", category: "CMS", confidence: "high", evidence: "X-Powered-By: WordPress" });

  } catch (err) {
    techResult = [{ error: (err as Error).message }];
  }

  // --- Section 4: Port Scan ---
  let portsResult: any = { scanned_count: 0, open_ports: [], details: [] };
  try {
    const portScanPromises = COMMON_PORTS.map(async ({ port, service }) => {
      let isOpen = false;
      let status = "closed";

      // 1. Try socket connection via Deno.connect if available
      let socketAttempted = false;
      if (typeof (Deno as any).connect === "function") {
        try {
          socketAttempted = true;
          const conn = await (Deno as any).connect({ hostname: host, port });
          isOpen = true;
          status = "open";
          try { conn.close(); } catch (_e) {}
        } catch (e: any) {
          const msg = (e.message || "").toLowerCase();
          if (msg.includes("refused")) {
            status = "closed";
          } else if (msg.includes("timeout") || msg.includes("timed out")) {
            status = "timeout";
          } else {
            status = "closed";
          }
        }
      }

      // 2. Fallback to fetch if socket wasn't available or port is web-related
      if (!socketAttempted || ([80, 443, 8080, 8443, 8888, 9090].includes(port) && !isOpen)) {
        try {
          const proto = [443, 8443].includes(port) ? "https" : "http";
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 1200);
          const pResp = await fetch(`${proto}://${host}:${port}/`, {
            signal: controller.signal,
            redirect: "manual",
          });
          clearTimeout(timer);
          if (pResp.status || pResp.type) {
            isOpen = true;
            status = "open";
          }
        } catch (fe: any) {
          const fmsg = (fe.message || "").toLowerCase();
          if (fmsg.includes("refused")) {
            status = "closed";
          } else if (fmsg.includes("abort") || fmsg.includes("timeout")) {
            status = "timeout";
          }
        }
      }

      return { port, service, open: isOpen, status };
    });

    const portResults = await Promise.allSettled(portScanPromises);
    const scannedDetails = portResults.map((res, i) => {
      if (res.status === "fulfilled") return res.value;
      return {
        port: COMMON_PORTS[i].port,
        service: COMMON_PORTS[i].service,
        open: false,
        status: "error",
      };
    });

    const openPorts = scannedDetails.filter((p) => p.open);
    portsResult = {
      scanned_count: COMMON_PORTS.length,
      open_count: openPorts.length,
      open_ports: openPorts,
      details: scannedDetails,
    };
  } catch (err) {
    portsResult = { status: "error", error: (err as Error).message };
  }

  // --- Section 5: API Endpoint Discovery ---
  let apisResult: any = { tested_count: 0, found_count: 0, found_endpoints: [] };
  try {
    const baseUrl = `${parsedTarget.protocol}//${parsedTarget.host}`;
    const apiScanPromises = API_PATHS.map(async (path) => {
      const fullUrl = `${baseUrl}${path}`;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2500);
        const resp = await fetch(fullUrl, {
          method: "GET",
          signal: controller.signal,
          redirect: "manual",
          headers: {
            "User-Agent": "Base44SecurityScanner/1.0",
          },
        });
        clearTimeout(timer);

        const status = resp.status;
        const isSensitive = SENSITIVE_PATHS.includes(path);
        // Exclude 404, 502, 503 as "not found/available"
        const isFound = ![404, 502, 503].includes(status);

        return {
          path,
          url: fullUrl,
          status,
          statusText: resp.statusText || String(status),
          accessible: [200, 201, 202, 204, 301, 302, 307, 308].includes(status),
          sensitive: isSensitive,
          isFound,
        };
      } catch (_e) {
        return {
          path,
          url: fullUrl,
          status: 0,
          statusText: "Connection Error / Timeout",
          accessible: false,
          sensitive: SENSITIVE_PATHS.includes(path),
          isFound: false,
        };
      }
    });

    const apiSettled = await Promise.allSettled(apiScanPromises);
    const apiResults = apiSettled
      .filter((res) => res.status === "fulfilled")
      .map((res: any) => res.value);

    const foundEndpoints = apiResults.filter((r) => r.isFound);
    const sensitiveExposed = foundEndpoints.filter(
      (r) => r.sensitive && r.accessible
    );

    apisResult = {
      tested_count: API_PATHS.length,
      found_count: foundEndpoints.length,
      sensitive_exposed_count: sensitiveExposed.length,
      found_endpoints: foundEndpoints,
    };
  } catch (err) {
    apisResult = { status: "error", error: (err as Error).message };
  }

  // --- Section 6: Secret Scanning ---
  let secretsResult: any = { found_count: 0, findings: [] };
  try {
    const secretRegexes = [
      { name: "AWS Access Key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
      { name: "Google API Key", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
      { name: "Stripe Live Secret Key", pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
      { name: "Slack Token", pattern: /\bxox[baprs]-[0-9a-zA-Z]{10,}\b/g },
      { name: "GitHub Access Token", pattern: /\bgh[pousr]_[0-9a-zA-Z]{36}\b/g },
      { name: "OpenAI API Key", pattern: /\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b/g },
      { name: "Twilio API Key", pattern: /\bSK[0-9a-fA-F]{32}\b/g },
      { name: "SendGrid API Key", pattern: /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g },
      { name: "Mailgun API Key", pattern: /\bkey-[0-9a-zA-Z]{32}\b/g },
      { name: "JWT Token", pattern: /\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g },
      { name: "Private Key", pattern: /-----BEGIN (?:RSA|EC|PGP|OPENSSH|DSA)? ?PRIVATE KEY-----[\s\S]*?-----END \1 ?PRIVATE KEY-----/g },
    ];

    const findings: any[] = [];
    for (const secretDef of secretRegexes) {
      const matches = responseText.match(secretDef.pattern);
      if (matches) {
        for (const match of matches) {
          let redacted = match;
          if (match.length > 8) {
            redacted = match.substring(0, 4) + "..." + match.substring(match.length - 4);
          } else {
            redacted = match.substring(0, 2) + "...";
          }
          findings.push({
            type: secretDef.name,
            match_redacted: redacted,
            location: "HTML Page Source",
          });
        }
      }
    }

    secretsResult = {
      found_count: findings.length,
      findings,
    };
  } catch (err) {
    secretsResult = { status: "error", error: (err as Error).message };
  }

  // --- Section 7: Cookie Security Analysis ---
  let cookiesResult: any = { total_cookies: 0, secure_cookies: 0, vulnerable_cookies: 0, details: [] };
  try {
    const cookieHeader = responseHeaders.get("set-cookie");
    if (cookieHeader) {
      const rawCookies = cookieHeader.split(/,\s*(?=[A-Za-z0-9_%=]+;)/);
      const analyzed: any[] = [];

      for (const rawCookie of rawCookies) {
        const parts = rawCookie.split(";").map((p) => p.trim());
        if (parts.length === 0) continue;

        const [nameValue, ...flags] = parts;
        const eqIdx = nameValue.indexOf("=");
        const name = eqIdx > -1 ? nameValue.substring(0, eqIdx) : nameValue;

        const flagStr = flags.join("; ").toLowerCase();
        const httpOnly = flagStr.includes("httponly");
        const secure = flagStr.includes("secure");
        
        let sameSite = "Not Set";
        if (flagStr.includes("samesite=strict")) sameSite = "Strict";
        else if (flagStr.includes("samesite=lax")) sameSite = "Lax";
        else if (flagStr.includes("samesite=none")) sameSite = "None";

        const issues: string[] = [];
        if (!httpOnly) issues.push("Missing HttpOnly flag (susceptible to XSS cookie theft)");
        if (!secure) issues.push("Missing Secure flag (transmitted over plaintext)");
        if (sameSite === "Not Set" || sameSite === "None") issues.push("SameSite flag missing or None (CSRF risk)");

        analyzed.push({
          name,
          httpOnly,
          secure,
          sameSite,
          issues,
          is_secure: issues.length === 0,
        });
      }

      const secCount = analyzed.filter((c) => c.is_secure).length;
      cookiesResult = {
        total_cookies: analyzed.length,
        secure_cookies: secCount,
        vulnerable_cookies: analyzed.length - secCount,
        details: analyzed,
      };
    }
  } catch (err) {
    cookiesResult = { status: "error", error: (err as Error).message };
  }

  // --- Section 8: CORS Policy Check ---
  let corsResult: any = { status: "unknown" };
  try {
    const allowOrigin = responseHeaders.get("access-control-allow-origin");
    const allowCreds = responseHeaders.get("access-control-allow-credentials");
    const allowMethods = responseHeaders.get("access-control-allow-methods");
    const allowHeaders = responseHeaders.get("access-control-allow-headers");

    const issues: string[] = [];
    let corsStatus = "secure";

    if (allowOrigin === "*") {
      issues.push("Wildcard Access-Control-Allow-Origin enabled");
      corsStatus = "warning";
      if (allowCreds === "true") {
        issues.push("CRITICAL: Wildcard origin combined with Allow-Credentials");
        corsStatus = "vulnerable";
      }
    }

    try {
      const optController = new AbortController();
      const optTimer = setTimeout(() => optController.abort(), 2000);
      const optResp = await fetch(targetUrl, {
        method: "OPTIONS",
        signal: optController.signal,
        headers: {
          "Origin": "https://attacker-domain.com",
          "Access-Control-Request-Method": "POST",
        },
      });
      clearTimeout(optTimer);

      const testOrigin = optResp.headers.get("access-control-allow-origin");
      if (testOrigin === "https://attacker-domain.com") {
        issues.push("Arbitrary Origin Reflected in Access-Control-Allow-Origin");
        corsStatus = "vulnerable";
      }
    } catch (_e) {
      // Ignore options check failure
    }

    corsResult = {
      allow_origin: allowOrigin,
      allow_credentials: allowCreds === "true",
      allow_methods: allowMethods,
      allow_headers: allowHeaders,
      status: corsStatus,
      issues,
    };
  } catch (err) {
    corsResult = { status: "error", error: (err as Error).message };
  }

  // --- Section 9: HTTP Method Check ---
  let allowedMethods: string[] = [];
  try {
    const optResp = await fetch(targetUrl, { method: "OPTIONS" });
    const allowHeader = optResp.headers.get("allow") || optResp.headers.get("access-control-allow-methods");
    if (allowHeader) {
      allowedMethods = allowHeader.split(",").map((m) => m.trim().toUpperCase());
    }
  } catch (_e) {
    allowedMethods = ["GET", "POST", "HEAD", "OPTIONS"];
  }

  // --- Section 10: Server Info & DNS ---
  let serverInfoResult: any = {};
  try {
    let dnsRecords: any = null;
    if (typeof (Deno as any).resolveDns === "function") {
      try {
        const aRecords = await (Deno as any).resolveDns(host, "A");
        dnsRecords = { A: aRecords };
      } catch (_e) {
        // DNS lookup failed or permission denied
      }
    }

    serverInfoResult = {
      hostname: host,
      protocol: parsedTarget.protocol,
      port: parsedTarget.port || (parsedTarget.protocol === "https:" ? "443" : "80"),
      response_status: initialResponse ? initialResponse.status : 0,
      response_time_ms: fetchTimeMs,
      server_header: responseHeaders.get("server") || null,
      powered_by: responseHeaders.get("x-powered-by") || null,
      via_header: responseHeaders.get("via") || null,
      cf_ray: responseHeaders.get("cf-ray") || null,
      allowed_methods: allowedMethods,
      dns_records: dnsRecords,
    };
  } catch (err) {
    serverInfoResult = { status: "error", error: (err as Error).message };
  }

  // --- Section 11: Score & Summary Calculation ---
  let score = 100;
  const criticalIssues: string[] = [];
  const highIssues: string[] = [];
  const mediumIssues: string[] = [];
  const lowIssues: string[] = [];

  // Deductions: Security Headers
  if (headersResult?.checks) {
    for (const c of headersResult.checks) {
      if (!c.present) {
        if (["Content-Security-Policy", "Strict-Transport-Security"].includes(c.header)) {
          score -= 10;
          highIssues.push(`Missing security header: ${c.header}`);
        } else {
          score -= 5;
          mediumIssues.push(`Missing security header: ${c.header}`);
        }
      }
    }
  }

  // Deductions: SSL
  if (!sslResult?.valid) {
    score -= 20;
    criticalIssues.push(`SSL/TLS Invalid or Not Enforced: ${sslResult?.details || 'Insecure'}`);
  }

  // Deductions: Secrets
  if (secretsResult?.found_count > 0) {
    const secDeduction = Math.min(secretsResult.found_count * 20, 40);
    score -= secDeduction;
    criticalIssues.push(`Exposed credentials/secrets in HTML source code (${secretsResult.found_count} found)`);
  }

  // Deductions: API / Sensitive Files
  if (apisResult?.sensitive_exposed_count > 0) {
    score -= 25;
    criticalIssues.push(`Sensitive files/endpoints publicly accessible (${apisResult.sensitive_exposed_count} exposed)`);
  }

  // Deductions: Cookies
  if (cookiesResult?.vulnerable_cookies > 0) {
    score -= Math.min(cookiesResult.vulnerable_cookies * 5, 15);
    mediumIssues.push(`Insecure cookies detected (${cookiesResult.vulnerable_cookies} with missing flags)`);
  }

  // Deductions: CORS
  if (corsResult?.status === "vulnerable") {
    score -= 15;
    highIssues.push("Vulnerable CORS policy detected");
  } else if (corsResult?.status === "warning") {
    score -= 5;
    lowIssues.push("CORS policy allows wildcard origin");
  }

  // Deductions: Dangerous Open Ports
  if (portsResult?.open_ports) {
    const dangerousPorts = [21, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017];
    const openDangerous = portsResult.open_ports.filter((p: any) => dangerousPorts.includes(p.port));
    if (openDangerous.length > 0) {
      score -= Math.min(openDangerous.length * 10, 30);
      highIssues.push(`Exposed sensitive database/service ports: ${openDangerous.map((p: any) => p.port + "/" + p.service).join(", ")}`);
    }
  }

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  let grade = "F";
  if (score >= 95) grade = "A+";
  else if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 60) grade = "D";

  const totalFindings =
    criticalIssues.length +
    highIssues.length +
    mediumIssues.length +
    lowIssues.length;

  const totalDurationMs = Date.now() - startTime;

  const summary = {
    grade,
    score,
    scan_duration_ms: totalDurationMs,
    total_findings: totalFindings,
    severity_counts: {
      critical: criticalIssues.length,
      high: highIssues.length,
      medium: mediumIssues.length,
      low: lowIssues.length,
    },
    critical_issues: criticalIssues,
    high_issues: highIssues,
    medium_issues: mediumIssues,
    low_issues: lowIssues,
    narrative: `Security scan completed for ${targetUrl} with grade ${grade} (${score}/100). Identified ${totalFindings} issue(s): ${criticalIssues.length} critical, ${highIssues.length} high, ${mediumIssues.length} medium, ${lowIssues.length} low.`,
  };

  const finalResponse = {
    target_url: targetUrl,
    scan_timestamp: new Date().toISOString(),
    score,
    summary,
    headers: headersResult,
    ssl: sslResult,
    tech: techResult,
    ports: portsResult,
    apis: apisResult,
    secrets: secretsResult,
    cookies: cookiesResult,
    cors: corsResult,
    server_info: serverInfoResult,
  };

  return new Response(JSON.stringify(finalResponse, null, 2), {
    status: 200,
    headers: CORS_HEADERS,
  });
});
