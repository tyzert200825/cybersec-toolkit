#!/usr/bin/env python3
"""
Elara SecOps — Standalone Pipeline Server
Runs in the sandbox, executes actual security tools, serves dashboard.
No Base44 dependency — fully standalone.
"""
import json, os, subprocess, threading, time, http.server, socketserver, sys
from urllib.parse import urlparse, parse_qs

PORT = 9191
ADMIN_KEY = "Fuckyou25.!"
WORK_DIR = os.path.dirname(os.path.abspath(__file__))

# ===== Results storage =====
RESULTS = {}  # job_id -> {status, output, results, started, finished}

# ===== Pipeline executors =====
def run_cmd(cmd, timeout=120):
    """Run a shell command and return output."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT: command exceeded time limit"
    except Exception as e:
        return f"ERROR: {e}"

def pipeline_oops_scanner(target=None):
    """Scan GitHub Archive for deleted commits with secrets."""
    out = run_cmd(f"cd {WORK_DIR} && python3 gh_secret_hunter.py --mode oops --limit 50 2>&1", timeout=180)
    return {"pipeline": "oops_scanner", "output": out[-5000:] if len(out)>5000 else out}

def pipeline_code_dorker(target=None):
    """GitHub code search with dork patterns."""
    out = run_cmd(f"cd {WORK_DIR} && python3 code_dorker.py --limit 20 2>&1", timeout=180)
    return {"pipeline": "code_dorker", "output": out[-5000:] if len(out)>5000 else out}

def pipeline_gh_archive(target=None):
    """Full GH Archive pipeline."""
    out = run_cmd(f"cd {WORK_DIR} && python3 gh_secret_hunter.py --mode archive --limit 100 2>&1", timeout=300)
    return {"pipeline": "gh_archive", "output": out[-5000:] if len(out)>5000 else out}

def pipeline_paste_monitor(target=None):
    """Monitor paste sites for leaked credentials."""
    out = run_cmd(f"cd {WORK_DIR} && python3 paste_monitor.py 2>&1", timeout=180)
    return {"pipeline": "paste_monitor", "output": out[-5000:] if len(out)>5000 else out}

def pipeline_google_dorker(target=None):
    """Google dorking for exposed secrets."""
    out = run_cmd(f"cd {WORK_DIR} && python3 google_dorker.py --limit 20 2>&1", timeout=180)
    return {"pipeline": "google_dorker", "output": out[-5000:] if len(out)>5000 else out}

def pipeline_nuclei_scan(target=None):
    """Run nuclei vulnerability scanner against target."""
    if not target:
        return {"pipeline": "nuclei_scan", "output": "ERROR: target required (domain or IP)"}
    out = run_cmd(f"nuclei -u {target} -severity low,medium,high,critical -silent -json 2>/dev/null | head -50", timeout=300)
    return {"pipeline": "nuclei_scan", "target": target, "output": out}

def pipeline_subfinder(target=None):
    """Enumerate subdomains."""
    if not target:
        return {"pipeline": "subfinder", "output": "ERROR: target domain required"}
    out = run_cmd(f"subfinder -d {target} -silent 2>&1 | head -100", timeout=120)
    return {"pipeline": "subfinder", "target": target, "output": out}

def pipeline_nmap(target=None):
    """Nmap service detection."""
    if not target:
        return {"pipeline": "nmap", "output": "ERROR: target required (IP or domain)"}
    out = run_cmd(f"nmap -sV -sS -T4 --top-ports 100 {target} 2>&1", timeout=300)
    return {"pipeline": "nmap", "target": target, "output": out}

def pipeline_shodan(target=None):
    """Shodan search (uses API if available, otherwise curl)."""
    if not target:
        return {"pipeline": "shodan_scan", "output": "ERROR: target required"}
    out = run_cmd(f"curl -s 'https://internetdb.shodan.io/{target}' 2>&1", timeout=30)
    return {"pipeline": "shodan_scan", "target": target, "output": out}

def pipeline_trufflehog(target=None):
    """Scan a git repo for secrets with TruffleHog."""
    if not target:
        return {"pipeline": "trufflehog", "output": "ERROR: target git repo URL required"}
    out = run_cmd(f"trufflehog git {target} --json 2>/dev/null | head -20", timeout=180)
    return {"pipeline": "trufflehog", "target": target, "output": out}

def pipeline_full_scan(target=None):
    """Run all secret hunting pipelines."""
    results = {}
    for name, fn in [("oops", pipeline_oops_scanner), ("dorker", pipeline_code_dorker), ("paste", pipeline_paste_monitor)]:
        try:
            r = fn()
            results[name] = r["output"][-1000:]
        except Exception as e:
            results[name] = f"ERROR: {e}"
    return {"pipeline": "full_scan", "output": json.dumps(results, indent=2)}

def pipeline_recon_full(target=None):
    """Full recon suite."""
    if not target:
        return {"pipeline": "recon_full", "output": "ERROR: target required"}
    results = {}
    results["subfinder"] = run_cmd(f"subfinder -d {target} -silent 2>&1 | head -50", timeout=120)
    results["nmap"] = run_cmd(f"nmap -sV -T4 --top-ports 50 {target} 2>&1", timeout=180)
    results["nuclei"] = run_cmd(f"nuclei -u {target} -severity medium,high,critical -silent 2>&1 | head -30", timeout=300)
    results["shodan"] = run_cmd(f"curl -s 'https://internetdb.shodan.io/{target}' 2>&1", timeout=30)
    return {"pipeline": "recon_full", "target": target, "output": json.dumps(results, indent=2)}

PIPELINES = {
    "oops_scanner": pipeline_oops_scanner,
    "code_dorker": pipeline_code_dorker,
    "gh_archive": pipeline_gh_archive,
    "paste_monitor": pipeline_paste_monitor,
    "google_dorker": pipeline_google_dorker,
    "nuclei_scan": pipeline_nuclei_scan,
    "subfinder": pipeline_subfinder,
    "nmap": pipeline_nmap,
    "shodan_scan": pipeline_shodan,
    "trufflehog": pipeline_trufflehog,
    "full_scan": pipeline_full_scan,
    "recon_full": pipeline_recon_full,
}

# ===== Job runner =====
def run_job(job_id, pipeline, target=None):
    fn = PIPELINES.get(pipeline)
    if not fn:
        RESULTS[job_id] = {"status": "error", "error": f"Unknown pipeline: {pipeline}", "finished": time.time()}
        return
    RESULTS[job_id] = {"status": "running", "started": time.time()}
    try:
        r = fn(target)
        RESULTS[job_id] = {"status": "complete", "output": r.get("output", ""), "pipeline": r.get("pipeline", pipeline), "target": target, "started": RESULTS[job_id]["started"], "finished": time.time()}
    except Exception as e:
        RESULTS[job_id] = {"status": "error", "error": str(e), "finished": time.time()}

# ===== HTTP handler =====
DASHBOARD_HTML = None
def load_dashboard():
    global DASHBOARD_HTML
    path = os.path.join(WORK_DIR, "dashboard_standalone.html")
    if os.path.exists(path):
        with open(path) as f:
            DASHBOARD_HTML = f.read()
    else:
        DASHBOARD_HTML = "<html><body><h1>Dashboard file not found</h1></body></html>"

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _html(self, content):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(content.encode())

    def do_OPTIONS(self):
        self._json({})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/" or path == "/dashboard":
            load_dashboard()
            self._html(DASHBOARD_HTML)
        elif path == "/api/jobs":
            self._json({"jobs": {k: {k2:v2 for k2,v2 in v.items()} for k,v in RESULTS.items()}})
        elif path == "/api/job":
            qs = parse_qs(parsed.query)
            job_id = qs.get("id", [None])[0]
            if job_id and job_id in RESULTS:
                self._json(RESULTS[job_id])
            else:
                self._json({"error": "job not found"})
        elif path == "/api/findings":
            self._json(get_findings())
        elif path == "/api/pipelines":
            self._json({"pipelines": list(PIPELINES.keys())})
        else:
            self._json({"error": "not found", "endpoints": ["/", "/api/jobs", "/api/job?id=X", "/api/findings", "/api/pipelines"]}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/run":
            self._json({"error": "use /api/run"}, 404)
            return
        try:
            body = json.loads(self.rfile.read(65536).decode())
        except:
            self._json({"error": "invalid JSON"}, 400)
            return
        auth = body.get("authKey", "")
        if auth != ADMIN_KEY:
            self._json({"error": "unauthorized"}, 401)
            return
        pipeline = body.get("pipeline", "")
        target = body.get("target")
        if pipeline not in PIPELINES:
            self._json({"error": f"unknown pipeline: {pipeline}", "available": list(PIPELINES.keys())}, 400)
            return
        job_id = f"{pipeline}_{int(time.time())}"
        t = threading.Thread(target=run_job, args=(job_id, pipeline, target), daemon=True)
        t.start()
        self._json({"job_id": job_id, "pipeline": pipeline, "target": target, "status": "running"})

def get_findings():
    """Load findings from JSON file."""
    path = os.path.join(WORK_DIR, "dashboard_data.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"findings": [], "stats": {"total": 0}}

def main():
    load_dashboard()
    print(f"[Elara SecOps] Server starting on port {PORT}")
    print(f"[Elara SecOps] Dashboard: http://localhost:{PORT}/")
    print(f"[Elara SecOps] Pipelines: {list(PIPELINES.keys())}")
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), Handler) as s:
        s.allow_reuse_address = True
        s.serve_forever()

if __name__ == "__main__":
    main()
