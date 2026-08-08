#!/usr/bin/env python3
"""
Upload findings to Base44 SecretFinding entity via backend function.
Usage: python3 upload_findings.py findings.json
"""

import json
import os
import sys
import urllib.request

BASE44_FUNCTION_URL = os.environ.get(
    "BASE44_PIPELINE_URL",
    "https://elara-6512927d.base44.app/functions/runPipeline"
)

def upload_findings(findings_path):
    with open(findings_path, "r") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        findings = findings.get("findings", [])

    if not findings:
        print("No findings to upload.")
        return

    print(f"Uploading {len(findings)} findings to Base44...")

    # Send in batches of 10
    batch_size = 10
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        payload = json.dumps({
            "pipeline": "import_findings",
            "findings": batch,
            "authKey": os.environ.get("ELARA_AUTH_KEY", "")
        }).encode()

        req = urllib.request.Request(
            BASE44_FUNCTION_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
                print(f"  Batch {i//batch_size + 1}: {result.get('status', 'done')}")
        except Exception as e:
            print(f"  Batch {i//batch_size + 1}: ERROR - {e}")

    print("Upload complete.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 upload_findings.py <findings.json>")
        sys.exit(1)
    upload_findings(sys.argv[1])
