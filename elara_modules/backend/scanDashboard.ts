import { createClientFromRequest } from "npm:@base44/sdk@0.8.31";

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const token = url.searchParams.get("t");
  const REQUIRED_TOKEN = "admin";
  const ADMIN_PW = "admin";

  // Requirement 1: Accept GET with query param ?t=admin for token auth. Without token return 404.
  if (req.method === "GET") {
    if (token !== REQUIRED_TOKEN) {
      return new Response("404 Not Found", {
        status: 404,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    // Serve Login Page
    return new Response(renderLoginPage(), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }

  // Requirement 3: After login (POST with form data pw=admin), show the scan dashboard
  if (req.method === "POST") {
    let password = "";
    try {
      const contentType = req.headers.get("content-type") || "";
      if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
        const formData = await req.formData();
        password = formData.get("pw")?.toString() || "";
      } else if (contentType.includes("application/json")) {
        const body = await req.json();
        password = body.pw || "";
      } else {
        const text = await req.text();
        const params = new URLSearchParams(text);
        password = params.get("pw") || "";
      }
    } catch (_) {
      // fallback
    }

    if (password === ADMIN_PW) {
      return new Response(renderScanDashboard(password), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    } else {
      return new Response(renderLoginPage("Invalid password. Please try again."), {
        status: 401,
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
  }

  return new Response("405 Method Not Allowed", { status: 405 });
});

function renderLoginPage(errorMsg: string = ""): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Elara SecOps — Scan Login</title>
<style>
  :root {
    --bg: #0a0e14;
    --card: #11161f;
    --border: #1e2733;
    --txt: #d4d4d4;
    --dim: #6b7280;
    --accent: #00d4aa;
    --accent-hover: #00b894;
    --red: #ff4444;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace, system-ui, -apple-system, sans-serif;
    background-color: var(--bg);
    color: var(--txt);
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 20px;
  }
  .login-box {
    background-color: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 36px 28px;
    width: 100%;
    max-width: 420px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    text-align: center;
  }
  .brand-tag {
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .title {
    color: var(--accent);
    font-size: 22px;
    font-weight: 700;
    margin-bottom: 12px;
  }
  .subtitle {
    color: var(--dim);
    font-size: 13px;
    line-height: 1.5;
    margin-bottom: 24px;
  }
  .field {
    text-align: left;
    margin-bottom: 20px;
  }
  .field label {
    display: block;
    font-size: 11px;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
    font-weight: 600;
  }
  .field input {
    width: 100%;
    padding: 12px 14px;
    background-color: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--txt);
    font-family: inherit;
    font-size: 14px;
    outline: none;
    transition: border-color 0.2s;
  }
  .field input:focus {
    border-color: var(--accent);
  }
  .err-msg {
    background: rgba(255, 68, 68, 0.1);
    border: 1px solid rgba(255, 68, 68, 0.3);
    color: var(--red);
    padding: 10px 12px;
    border-radius: 6px;
    font-size: 12px;
    margin-bottom: 20px;
    text-align: left;
  }
  .btn-submit {
    width: 100%;
    padding: 14px;
    background-color: var(--accent);
    color: var(--bg);
    border: none;
    border-radius: 8px;
    font-family: inherit;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
    transition: background-color 0.2s;
    letter-spacing: 1px;
  }
  .btn-submit:hover {
    background-color: var(--accent-hover);
  }
  .footer-text {
    margin-top: 24px;
    font-size: 10px;
    color: var(--dim);
  }
</style>
</head>
<body>
  <div class="login-box">
    <div class="brand-tag">ELARA SECOPS</div>
    <div class="title">Website Scanner</div>
    <div class="subtitle">Enter administrator password to access the website scanning dashboard.</div>
    
    <form method="POST" action="?t=admin">
      <div class="field">
        <label for="pw">PASSWORD</label>
        <input type="password" id="pw" name="pw" placeholder="Enter password" required autofocus autocomplete="current-password" />
      </div>
      ${errorMsg ? `<div class="err-msg">⚠️ ${errorMsg}</div>` : ""}
      <button type="submit" class="btn-submit">UNLOCK SCANNER</button>
    </form>

    <div class="footer-text">Protected Portal &bull; Elara Security Suite 2026</div>
  </div>
</body>
</html>`;
}

function renderScanDashboard(authPw: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Elara SecOps — Website Scan Dashboard</title>
<style>
  :root {
    --bg: #0a0e14;
    --card: #11161f;
    --hover: #1a2030;
    --border: #1e2733;
    --txt: #d4d4d4;
    --dim: #6b7280;
    --accent: #00d4aa;
    --accent-dark: #00b894;
    --green: #2ed573;
    --yellow: #ffa502;
    --red: #ff4757;
    --blue: #54a0ff;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace, system-ui, -apple-system, sans-serif;
    background-color: var(--bg);
    color: var(--txt);
    min-height: 100vh;
    padding-bottom: 40px;
  }
  .hdr {
    background: var(--card);
    border-bottom: 1px solid var(--border);
    padding: 14px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 100;
    flex-wrap: wrap;
    gap: 12px;
  }
  .hdr-brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .hdr-brand h1 {
    color: var(--accent);
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 0.5px;
  }
  .hdr-badge {
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 4px;
    background: rgba(0, 212, 170, 0.15);
    color: var(--accent);
    border: 1px solid rgba(0, 212, 170, 0.3);
  }
  .btn-logout {
    background: none;
    border: 1px solid var(--border);
    color: var(--dim);
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    font-family: inherit;
    font-size: 12px;
    text-decoration: none;
    transition: all 0.2s;
  }
  .btn-logout:hover {
    border-color: var(--red);
    color: var(--red);
  }
  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 24px 16px;
  }
  .scan-box {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
  }
  .scan-box h2 {
    font-size: 15px;
    color: var(--txt);
    margin-bottom: 6px;
  }
  .scan-box p {
    font-size: 12px;
    color: var(--dim);
    margin-bottom: 16px;
  }
  .input-grp {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
  }
  .input-grp input {
    flex: 1;
    min-width: 260px;
    padding: 12px 16px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--txt);
    font-family: inherit;
    font-size: 14px;
    outline: none;
  }
  .input-grp input:focus {
    border-color: var(--accent);
  }
  .btn-p {
    padding: 12px 24px;
    background: var(--accent);
    color: var(--bg);
    border: none;
    border-radius: 8px;
    font-family: inherit;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.2s;
    white-space: nowrap;
  }
  .btn-p:hover {
    background: var(--accent-dark);
  }
  .btn-p:disabled {
    opacity: 0.6;
    cursor: wait;
  }
  .presets {
    display: flex;
    gap: 8px;
    margin-top: 12px;
    flex-wrap: wrap;
    align-items: center;
  }
  .preset-lbl {
    font-size: 11px;
    color: var(--dim);
  }
  .preset-btn {
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--dim);
    font-size: 11px;
    padding: 4px 10px;
    border-radius: 4px;
    cursor: pointer;
    font-family: inherit;
  }
  .preset-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }
  
  /* Loading & Error */
  #loadingArea {
    display: none;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 40px 20px;
    text-align: center;
    margin-bottom: 24px;
  }
  .spinner {
    display: inline-block;
    width: 36px;
    height: 36px;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin-bottom: 16px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .loading-title {
    font-size: 16px;
    font-weight: 600;
    color: var(--accent);
    margin-bottom: 8px;
  }
  .loading-sub {
    font-size: 12px;
    color: var(--dim);
  }

  #errorArea {
    display: none;
    background: rgba(255, 71, 87, 0.1);
    border: 1px solid rgba(255, 71, 87, 0.3);
    color: var(--red);
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 24px;
    font-size: 13px;
  }

  /* Results Dashboard */
  #resultsArea {
    display: none;
  }
  .summary-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 20px;
  }
  .score-box {
    display: flex;
    align-items: center;
    gap: 20px;
  }
  .score-circle {
    width: 90px;
    height: 90px;
    border-radius: 50%;
    border: 4px solid var(--accent);
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    background: var(--bg);
  }
  .score-num {
    font-size: 28px;
    font-weight: 800;
    line-height: 1;
  }
  .score-max {
    font-size: 10px;
    color: var(--dim);
    margin-top: 2px;
  }
  .score-meta h3 {
    font-size: 18px;
    color: var(--txt);
    margin-bottom: 4px;
  }
  .score-meta p {
    font-size: 12px;
    color: var(--dim);
  }
  .action-btns {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
  }
  .btn-sec {
    padding: 10px 16px;
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--txt);
    border-radius: 8px;
    cursor: pointer;
    font-family: inherit;
    font-size: 12px;
    transition: all 0.2s;
  }
  .btn-sec:hover {
    border-color: var(--accent);
    color: var(--accent);
  }

  /* Grid of 9 Cards */
  .cards-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
    gap: 20px;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    display: flex;
    flex-direction: column;
  }
  .card.card-good { border-left: 4px solid var(--green); }
  .card.card-warning { border-left: 4px solid var(--yellow); }
  .card.card-bad { border-left: 4px solid var(--red); }

  .card-hdr {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
  .card-title {
    font-size: 14px;
    font-weight: 700;
    color: var(--txt);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .badge-status {
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 700;
    text-transform: uppercase;
  }
  .badge-good { background: rgba(46, 213, 115, 0.15); color: var(--green); }
  .badge-warning { background: rgba(255, 165, 2, 0.15); color: var(--yellow); }
  .badge-bad { background: rgba(255, 71, 87, 0.15); color: var(--red); }

  .items-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
    flex: 1;
  }
  .item-row {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    font-size: 12px;
  }
  .item-hdr {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
  }
  .item-name {
    font-weight: 600;
    color: var(--txt);
    word-break: break-all;
  }
  .item-det {
    color: var(--dim);
    font-size: 11px;
    word-break: break-all;
    white-space: pre-wrap;
    line-height: 1.4;
  }

  /* Export Popup Modal */
  .modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.75);
    z-index: 200;
    justify-content: center;
    align-items: center;
    padding: 16px;
  }
  .modal-overlay.active {
    display: flex;
  }
  .modal-box {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    width: 100%;
    max-width: 700px;
    max-height: 85vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 15px 40px rgba(0,0,0,0.6);
  }
  .modal-hdr {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }
  .modal-title {
    font-size: 16px;
    font-weight: 700;
    color: var(--accent);
  }
  .modal-close {
    cursor: pointer;
    color: var(--dim);
    font-size: 20px;
    background: none;
    border: none;
  }
  .modal-close:hover { color: var(--red); }
  .export-ta {
    width: 100%;
    height: 320px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--accent);
    font-family: inherit;
    font-size: 11px;
    padding: 12px;
    resize: none;
    outline: none;
    white-space: pre;
    overflow: auto;
  }
  .modal-ftr {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 16px;
  }

  @media (max-width: 600px) {
    .container { padding: 16px 10px; }
    .cards-grid { grid-template-columns: 1fr; }
    .summary-card { flex-direction: column; align-items: flex-start; }
  }
</style>
</head>
<body>
  <div class="hdr">
    <div class="hdr-brand">
      <h1>ELARA SECOPS</h1>
      <span class="hdr-badge">WEBSITE SCANNER</span>
    </div>
    <a href="?t=admin" class="btn-logout">LOGOUT</a>
  </div>

  <div class="container">
    <div class="scan-box">
      <h2>Target Website Scan</h2>
      <p>Enter a URL to perform deep automated security scanning (Headers, SSL, Tech, Ports, APIs, Secrets, Cookies, CORS, Server Info).</p>
      
      <div class="input-grp">
        <input type="url" id="targetUrl" placeholder="https://example.com" value="" autocomplete="off" />
        <button id="scanBtn" onclick="runScan()" class="btn-p">⚡ SCAN</button>
      </div>

      <div class="presets">
        <span class="preset-lbl">Quick Presets:</span>
        <button class="preset-btn" onclick="setTarget('https://example.com')">example.com</button>
        <button class="preset-btn" onclick="setTarget('https://github.com')">github.com</button>
        <button class="preset-btn" onclick="setTarget('https://base44.app')">base44.app</button>
      </div>
    </div>

    <div id="loadingArea">
      <div class="spinner"></div>
      <div class="loading-title">SCANNING TARGET WEBSITE...</div>
      <div class="loading-sub" id="loadingStatus">Connecting to scan engine and analyzing target host...</div>
    </div>

    <div id="errorArea"></div>

    <div id="resultsArea">
      <div class="summary-card">
        <div class="score-box">
          <div class="score-circle" id="scoreCircle">
            <div class="score-num" id="scoreNum">--</div>
            <div class="score-max">/ 100</div>
          </div>
          <div class="score-meta">
            <h3 id="targetHeading">Target Website</h3>
            <p id="scoreSummary">Security Score calculated across 9 assessment vectors.</p>
          </div>
        </div>
        <div class="action-btns">
          <button class="btn-sec" onclick="openExportModal('json')">📥 EXPORT JSON</button>
          <button class="btn-sec" onclick="openExportModal('csv')">📊 EXPORT CSV</button>
        </div>
      </div>

      <div class="cards-grid" id="cardsGrid">
        <!-- 9 Section Cards will be rendered here -->
      </div>
    </div>
  </div>

  <!-- Export Modal Popup -->
  <div class="modal-overlay" id="exportModal">
    <div class="modal-box">
      <div class="modal-hdr">
        <div class="modal-title" id="exportModalTitle">Export Results</div>
        <button class="modal-close" onclick="closeExportModal()">&times;</button>
      </div>
      <textarea class="export-ta" id="exportTextarea" readonly></textarea>
      <div class="modal-ftr">
        <button class="btn-sec" id="copyBtn" onclick="copyExportText()">📋 COPY</button>
        <button class="btn-sec" onclick="downloadExportFile()">💾 DOWNLOAD</button>
        <button class="btn-p" onclick="closeExportModal()">DONE</button>
      </div>
    </div>
  </div>

<script>
  const AUTH_PW = ${JSON.stringify(authPw)};
  let lastScanData = null;
  let lastScanUrl = "";
  let currentExportFormat = "json";

  function setTarget(url) {
    document.getElementById('targetUrl').value = url;
  }

  async function runScan() {
    const urlInput = document.getElementById('targetUrl');
    let rawUrl = urlInput.value.trim();
    if (!rawUrl) {
      alert('Please enter a website address.');
      urlInput.focus();
      return;
    }

    if (!/^https?:\/\//i.test(rawUrl)) {
      rawUrl = 'https://' + rawUrl;
      urlInput.value = rawUrl;
    }

    const scanBtn = document.getElementById('scanBtn');
    const loadingArea = document.getElementById('loadingArea');
    const resultsArea = document.getElementById('resultsArea');
    const errorArea = document.getElementById('errorArea');

    scanBtn.disabled = true;
    scanBtn.innerText = '⌛ SCANNING...';
    loadingArea.style.display = 'block';
    resultsArea.style.display = 'none';
    errorArea.style.display = 'none';

    let step = 0;
    const steps = [
      "Establishing connection to target host...",
      "Inspecting Security Headers & SSL Certificate...",
      "Fingerprinting Technology Stack & Open Ports...",
      "Scanning API Endpoints & exposed Secrets...",
      "Auditing Cookie flags & CORS policy...",
      "Gathering Server Info & computing Security Score..."
    ];
    const stepInterval = setInterval(() => {
      step = (step + 1) % steps.length;
      document.getElementById('loadingStatus').innerText = steps[step];
    }, 1200);

    try {
      const res = await fetch('https://elara-6512927d.base44.app/functions/websiteScan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: rawUrl,
          pw: AUTH_PW
        })
      });

      clearInterval(stepInterval);

      if (!res.ok) {
        const errText = await res.text();
        let errJson;
        try { errJson = JSON.parse(errText); } catch(_) {}
        throw new Error((errJson && errJson.error) || errText || ('HTTP ' + res.status));
      }

      const data = await res.json();
      if (data.error) {
        throw new Error(data.error);
      }

      lastScanData = data;
      lastScanUrl = rawUrl;
      renderResults(data, rawUrl);
      resultsArea.style.display = 'block';
    } catch (err) {
      clearInterval(stepInterval);
      errorArea.innerText = 'Scan Error: ' + err.message;
      errorArea.style.display = 'block';
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerText = '⚡ SCAN';
      loadingArea.style.display = 'none';
    }
  }

  function renderResults(data, targetUrl) {
    document.getElementById('targetHeading').innerText = targetUrl;

    const sections = {
      "Security Headers": data.securityHeaders || data.security_headers || data.headers,
      "SSL/TLS": data.ssl || data.tls || data.sslTls || data.ssl_tls,
      "Technology": data.technology || data.technologies || data.tech,
      "Open Ports": data.openPorts || data.open_ports || data.ports,
      "API Endpoints": data.apiEndpoints || data.api_endpoints || data.endpoints,
      "Secrets Found": data.secretsFound || data.secrets_found || data.secrets,
      "Cookies": data.cookies,
      "CORS": data.cors || data.corsPolicy || data.cors_policy,
      "Server Info": data.serverInfo || data.server_info || data.server
    };

    const normalizedSections = {};
    let totalBad = 0;
    let totalWarning = 0;
    let totalGood = 0;

    Object.keys(sections).forEach(secName => {
      const normItems = normalizeSection(sections[secName], secName);
      normalizedSections[secName] = normItems;

      normItems.forEach(it => {
        if (it.status === 'bad') totalBad++;
        else if (it.status === 'warning') totalWarning++;
        else totalGood++;
      });
    });

    let score = 100;
    if (typeof data.score === 'number') score = Math.round(data.score);
    else if (typeof data.securityScore === 'number') score = Math.round(data.securityScore);
    else if (typeof data.security_score === 'number') score = Math.round(data.security_score);
    else score = Math.max(0, 100 - (totalBad * 15) - (totalWarning * 5));

    const scoreCircle = document.getElementById('scoreCircle');
    const scoreNum = document.getElementById('scoreNum');
    scoreNum.innerText = score;

    let scoreColor = 'var(--green)';
    let scoreText = 'SECURE (LOW RISK)';
    if (score < 50) {
      scoreColor = 'var(--red)';
      scoreText = 'CRITICAL RISK (ATTENTION REQUIRED)';
    } else if (score < 80) {
      scoreColor = 'var(--yellow)';
      scoreText = 'MODERATE RISK (WARNINGS DETECTED)';
    }

    scoreCircle.style.borderColor = scoreColor;
    scoreNum.style.color = scoreColor;
    document.getElementById('scoreSummary').innerText = scoreText + ' — ' + totalBad + ' Critical, ' + totalWarning + ' Warnings, ' + totalGood + ' Passed.';

    const cardsGrid = document.getElementById('cardsGrid');
    cardsGrid.innerHTML = '';

    Object.keys(normalizedSections).forEach(secName => {
      const items = normalizedSections[secName];
      let hasBad = items.some(i => i.status === 'bad');
      let hasWarn = items.some(i => i.status === 'warning');

      let cardClass = 'card-good';
      let secBadgeText = 'PASS';
      let secBadgeClass = 'badge-good';

      if (hasBad) {
        cardClass = 'card-bad';
        secBadgeText = 'FAIL';
        secBadgeClass = 'badge-bad';
      } else if (hasWarn) {
        cardClass = 'card-warning';
        secBadgeText = 'WARN';
        secBadgeClass = 'badge-warning';
      }

      const card = document.createElement('div');
      card.className = 'card ' + cardClass;

      let itemsHtml = items.map(it => {
        let bClass = it.status === 'bad' ? 'badge-bad' : (it.status === 'warning' ? 'badge-warning' : 'badge-good');
        return '<div class="item-row"><div class="item-hdr"><span class="item-name">' + escapeHtml(it.name) + '</span><span class="badge-status ' + bClass + '">' + it.status.toUpperCase() + '</span></div><div class="item-det">' + escapeHtml(it.details) + '</div></div>';
      }).join('');

      card.innerHTML = '<div class="card-hdr"><div class="card-title">' + secName + '</div><span class="badge-status ' + secBadgeClass + '">' + secBadgeText + '</span></div><div class="items-list">' + itemsHtml + '</div>';
      cardsGrid.appendChild(card);
    });
  }

  function normalizeSection(raw, secName) {
    if (!raw) {
      if (secName === "Secrets Found") {
        return [{ name: "Secrets Audit", status: "good", details: "No sensitive API keys, tokens or secrets exposed." }];
      }
      return [{ name: secName, status: "good", details: "No issues or details recorded for this vector." }];
    }

    const items = [];
    if (Array.isArray(raw)) {
      if (raw.length === 0) {
        return [{ name: secName, status: "good", details: "No issues or findings recorded." }];
      }
      raw.forEach(item => {
        if (typeof item === 'string') {
          items.push({ name: item, status: inferStatus(item), details: item });
        } else if (typeof item === 'object' && item !== null) {
          const name = item.name || item.header || item.port || item.endpoint || item.key || item.type || item.title || "Item";
          const details = item.value || item.details || item.description || item.reason || (typeof item === 'object' ? JSON.stringify(item) : String(item));
          let status = item.status ? String(item.status).toLowerCase() : inferStatus(name + ' ' + details);
          if (!['good', 'warning', 'bad'].includes(status)) {
            status = inferStatus(name + ' ' + details + ' ' + status);
          }
          items.push({ name: String(name), status, details: String(details) });
        }
      });
    } else if (typeof raw === 'object' && raw !== null) {
      const keys = Object.keys(raw);
      if (keys.length === 0) {
        return [{ name: secName, status: "good", details: "No issues recorded." }];
      }
      keys.forEach(k => {
        const v = raw[k];
        let detailsStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
        let status = inferStatus(k + ' ' + detailsStr);
        items.push({ name: k, status, details: detailsStr });
      });
    } else {
      items.push({ name: secName, status: inferStatus(String(raw)), details: String(raw) });
    }

    return items;
  }

  function inferStatus(text) {
    const t = text.toLowerCase();
    if (t.includes('missing') || t.includes('expired') || t.includes('unsecured') || t.includes('vulnerable') || t.includes('leak') || t.includes('exposed') || t.includes('critical') || t.includes('fail') || t.includes('error') || t.includes('bad') || t.includes('open port 22') || t.includes('open port 3306')) {
      return 'bad';
    }
    if (t.includes('warn') || t.includes('outdated') || t.includes('medium') || t.includes('notice') || t.includes('info') || t.includes('deprecated') || t.includes('low')) {
      return 'warning';
    }
    return 'good';
  }

  function escapeHtml(str) {
    return String(str || '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function openExportModal(fmt) {
    if (!lastScanData) {
      alert('No scan results to export.');
      return;
    }

    currentExportFormat = fmt;
    const modal = document.getElementById('exportModal');
    const ta = document.getElementById('exportTextarea');
    const title = document.getElementById('exportModalTitle');

    if (fmt === 'json') {
      title.innerText = 'Export Results — JSON';
      ta.value = JSON.stringify(lastScanData, null, 2);
    } else {
      title.innerText = 'Export Results — CSV';
      ta.value = generateCSV(lastScanData, lastScanUrl);
    }

    modal.classList.add('active');
  }

  function closeExportModal() {
    document.getElementById('exportModal').classList.remove('active');
  }

  function copyExportText() {
    const ta = document.getElementById('exportTextarea');
    ta.select();
    navigator.clipboard.writeText(ta.value).then(() => {
      const copyBtn = document.getElementById('copyBtn');
      copyBtn.innerText = '✓ COPIED!';
      setTimeout(() => { copyBtn.innerText = '📋 COPY'; }, 2000);
    }).catch(() => {
      document.execCommand('copy');
      alert('Copied to clipboard!');
    });
  }

  function downloadExportFile() {
    const ta = document.getElementById('exportTextarea');
    const ext = currentExportFormat;
    const filename = 'website_scan_' + (lastScanUrl.replace(/[^a-zA-Z0-9]/g, '_')) + '.' + ext;
    const blob = new Blob([ta.value], { type: ext === 'json' ? 'application/json' : 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  function generateCSV(data, url) {
    const sections = {
      "Security Headers": data.securityHeaders || data.security_headers || data.headers,
      "SSL/TLS": data.ssl || data.tls || data.sslTls || data.ssl_tls,
      "Technology": data.technology || data.technologies || data.tech,
      "Open Ports": data.openPorts || data.open_ports || data.ports,
      "API Endpoints": data.apiEndpoints || data.api_endpoints || data.endpoints,
      "Secrets Found": data.secretsFound || data.secrets_found || data.secrets,
      "Cookies": data.cookies,
      "CORS": data.cors || data.corsPolicy || data.cors_policy,
      "Server Info": data.serverInfo || data.server_info || data.server
    };

    const rows = [["Target URL", "Section", "Item Name", "Status", "Details"].join(",")];

    Object.keys(sections).forEach(secName => {
      const items = normalizeSection(sections[secName], secName);
      items.forEach(it => {
        const u = '"' + url.replace(/"/g, '""') + '"';
        const s = '"' + secName.replace(/"/g, '""') + '"';
        const n = '"' + (it.name || "").replace(/"/g, '""') + '"';
        const st = '"' + (it.status || "").toUpperCase() + '"';
        const d = '"' + (it.details || "").replace(/"/g, '""').replace(/
/g, ' ') + '"';
        rows.push([u, s, n, st, d].join(","));
      });
    });

    return rows.join("
");
  }
</script>
</body>
</html>`;
}
