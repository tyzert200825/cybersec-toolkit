import requests
import json
import time

findings = [
    {
        "id": "f4",
        "type": "Google OAuth Client Secret",
        "secret": "GOCSPX-REDACTED",
        "client_id": "104367013752-bd1jq1ovfljnhaplbthh3v6fopubnrg0.apps.googleusercontent.com",
        "repo": "hngprojects/Reconcile-AI-BE",
        "file": ".env.save"
    },
    {
        "id": "f5",
        "type": "Google OAuth Client Secret",
        "secret": "GOCSPX-REDACTED",
        "client_id": "777461284594-dhgao2eek53ppl4o188ik2i9cigdcmnp.apps.googleusercontent.com",
        "repo": "voquill/voquill",
        "file": ".env.enterprise"
    },
    {
        "id": "f7",
        "type": "Google OAuth Client Secret",
        "secret": "GOCSPX-REDACTED",
        "client_id": "778214168359-nbgt0dedeol36gl425o5nqt5kaksh38u.apps.googleusercontent.com",
        "repo": "voquill/voquill",
        "file": ".env.enterprise-dev"
    },
    {
        "id": "f21",
        "type": "Firebase API Key",
        "secret": "AIzaSyREDACTED",
        "project": "voquill-prod",
        "repo": "voquill/voquill",
        "file": ".env.enterprise"
    },
    {
        "id": "f23",
        "type": "Firebase API Key",
        "secret": "AIzaSyREDACTED",
        "project": "voquill-dev",
        "repo": "voquill/voquill",
        "file": ".env.enterprise-dev"
    },
    {
        "id": "f24",
        "type": "Firebase API Key",
        "secret": "AIzaSyREDACTED",
        "project": "taho-production",
        "repo": "tahowallet/taho.xyz",
        "file": ".env.prd"
    },
    {
        "id": "f25",
        "type": "Firebase API Key",
        "secret": "AIzaSyREDACTED",
        "project": "taho-staging",
        "repo": "tahowallet/taho.xyz",
        "file": ".env.stg"
    },
    {
        "id": "f11",
        "type": "Azure Storage Key",
        "secret": "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
        "account": "devstoreaccount1",
        "repo": "yugabyte/yugabyte-db",
        "file": ".devcontainer/.env"
    }
]

results = []

for f in findings:
    print(f"\n--- Verifying {f['id']}: {f['type']} ({f['repo']}) ---")
    verified = False
    detail = ""
    
    if f["type"] == "Google OAuth Client Secret":
        # Test by attempting token exchange with a dummy code
        # If the client secret is valid, Google returns "invalid_grant" (bad auth code)
        # If the client secret is invalid, Google returns "invalid_client"
        try:
            resp = requests.post("https://oauth2.googleapis.com/token", 
                data={
                    "client_id": f["client_id"],
                    "client_secret": f["secret"],
                    "grant_type": "authorization_code",
                    "code": "4/0test_invalid_code_for_verification",
                    "redirect_uri": "http://localhost"
                }, timeout=10)
            error = resp.json().get("error", "")
            if error == "invalid_grant":
                verified = True
                detail = "VERIFIED — Client secret accepted by Google. Error 'invalid_grant' means the secret is valid but the auth code is fake (expected). The secret is LIVE and can be used for OAuth flows."
            elif error == "invalid_client":
                verified = False
                detail = "INVALID — Google rejected the client secret. Secret has been rotated or revoked."
            else:
                detail = f"Response: {resp.json()}"
        except Exception as e:
            detail = f"Error: {e}"
    
    elif f["type"] == "Firebase API Key":
        # Test by calling Firebase Identity Toolkit with the API key
        # If valid, returns "MISSING_EMAIL" or similar
        # If invalid, returns "API_KEY_INVALID"
        try:
            resp = requests.post(
                f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={f['secret']}",
                json={"returnSecureToken": False},
                timeout=10)
            error = resp.json().get("error", {})
            msg = error.get("message", "")
            if "API_KEY_INVALID" in msg or "INVALID_API_KEY" in msg:
                verified = False
                detail = f"INVALID — Firebase rejected the API key. Key has been revoked. ({msg})"
            elif "MISSING" in msg or "MISSING_EMAIL" in msg or "OPERATION_NOT_ALLOWED" in msg:
                verified = True
                detail = f"VERIFIED — Firebase API key is LIVE. Response: {msg}. Key is active and can access {f.get('project','')} Firebase project (Firestore, Auth, etc)."
            elif resp.status_code == 200:
                verified = True
                detail = "VERIFIED — Firebase API key accepted."
            else:
                detail = f"Response ({resp.status_code}): {resp.text[:200]}"
        except Exception as e:
            detail = f"Error: {e}"
    
    elif f["type"] == "Azure Storage Key":
        # Known Azurite emulator key — mark as false positive
        if f["account"] == "devstoreaccount1" and f["secret"] == "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==":
            verified = False
            detail = "FALSE POSITIVE — This is the well-known Azurite (Azure Storage emulator) development key. Not a real Azure Storage account key. Documented in Microsoft's Azurite docs."
        else:
            try:
                resp = requests.get(
                    f"https://{f['account']}.blob.core.windows.net/?comp=list",
                    headers={"x-ms-version": "2020-04-08", "Authorization": f"SharedKey {f['account']}:{f['secret']}"},
                    timeout=10)
                if resp.status_code == 200:
                    verified = True
                    detail = "VERIFIED — Azure Storage key is live. Can list all blobs in the account."
                else:
                    detail = f"Response ({resp.status_code}): {resp.text[:200]}"
            except Exception as e:
                detail = f"Error: {e}"
    
    result = {**f, "verified": verified, "detail": detail}
    results.append(result)
    print(f"  Result: {'✅ VERIFIED' if verified else '❌ NOT VERIFIED'}")
    print(f"  Detail: {detail}")
    time.sleep(1)  # Rate limit

print("\n\n=== SUMMARY ===")
verified_count = sum(1 for r in results if r["verified"])
print(f"Total tested: {len(results)}")
print(f"Verified (LIVE): {verified_count}")
print(f"Not verified: {len(results) - verified_count}")
for r in results:
    status = "✅ LIVE" if r["verified"] else "❌ DEAD"
    print(f"  {status} | {r['id']} | {r['type']} | {r['repo']}")

with open("verification_results.json", "w") as out:
    json.dump(results, out, indent=2)
print("\nResults saved to verification_results.json")
