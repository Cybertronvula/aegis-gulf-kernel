Aegis Gulf Compliance Kernel v1.0.0
AES-256-GCM encryption + SHA-256 HMAC audit chain
POPIA Section 19 compliant — South Africa

Quick Start
Run the live demo (30 seconds)
bashpython3 demo.py
Run the API server
bashpython3 server.py
Run in Docker
bashdocker build -t aegisgulf/kernel:1.0.0 .
docker run -p 8000:8000 aegisgulf/kernel:1.0.0

API Endpoints
MethodEndpointDescriptionGET/healthHealth checkGET/statsVault and performance statsPOST/archiveArchive an encrypted log entryGET/verifyVerify full audit chainGET/vaultExport recent vault entriesGET/benchmark?count=10000Live throughput benchmarkPOST/demo/tamperTamper demo (shows detection)

Archive a log entry
bashcurl -X POST http://localhost:8000/archive \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "user_consent_captured",
    "payload": {
      "user_id": "ZA-082-9912",
      "consent_scope": ["marketing"],
      "ip_hash": "sha256:a3f8..."
    },
    "metadata": {"popia_section": "S.18"}
  }'
Verify the audit chain
bashcurl http://localhost:8000/verify
Run a live benchmark
bashcurl "http://localhost:8000/benchmark?count=10000"

Requirements

Python 3.12+
cryptography library (pip install cryptography)
Aegis Gulf — Kimberley, Northern Cape, South Africa
Securing the Future
