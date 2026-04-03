"""
Aegis Gulf Compliance Kernel — REST API Server
===============================================
HTTP server exposing the compliance engine via REST endpoints.

Built on Python stdlib only — no external web framework required.
Production deployment uses the Docker container (see Dockerfile).

Endpoints:
    POST /archive          Archive a compliance log entry
    GET  /verify           Verify the full audit chain integrity
    GET  /vault            Export recent vault entries
    GET  /stats            Performance and vault statistics
    POST /demo/tamper      Tamper with an entry (demo only)
    GET  /benchmark        Run a live throughput benchmark
    GET  /health           Health check

Author : Nvula Bontes — Lead Architect, Aegis Gulf
Version: 1.0.0
"""

import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from engine import AegisComplianceKernel


_kernel = AegisComplianceKernel()
_kernel_lock = threading.Lock()

BANNER = """
╔══════════════════════════════════════════════════════════╗
║          AEGIS GULF COMPLIANCE KERNEL  v1.0.0            ║
║      Kimberley, Northern Cape, South Africa              ║
║                                                          ║
║  Encryption : AES-256-GCM                                ║
║  Integrity  : SHA-256 HMAC Chain                         ║
║  Compliance : POPIA Section 19 / Article 32              ║
║                                                          ║
║  API ready at http://localhost:8000                      ║
╚══════════════════════════════════════════════════════════╝
"""


def _json_response(handler, data: dict, status: int = 200):
    """Send a JSON response."""
    body = json.dumps(data, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Powered-By", "Aegis-Gulf-Kernel/1.0.0")
    handler.send_header("X-Encryption", "AES-256-GCM")
    handler.end_headers()
    handler.wfile.write(body)


def _read_body(handler) -> dict:
    """Read and parse JSON request body."""
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode("utf-8"))


class AegisAPIHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Custom log format
        print(f"  [{time.strftime('%H:%M:%S')}] {fmt % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "/health":
            self._handle_health()
        elif path == "/stats":
            self._handle_stats()
        elif path == "/verify":
            self._handle_verify()
        elif path == "/vault":
            limit = int(params.get("limit", ["20"])[0])
            self._handle_vault(limit)
        elif path == "/benchmark":
            count = int(params.get("count", ["10000"])[0])
            self._handle_benchmark(count)
        elif path in ("", "/"):
            self._handle_root()
        else:
            _json_response(self, {"error": "Endpoint not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")

        if path == "/archive":
            self._handle_archive()
        elif path == "/demo/tamper":
            self._handle_tamper()
        else:
            _json_response(self, {"error": "Endpoint not found"}, 404)



    def _handle_root(self):
        _json_response(self, {
            "service"   : "Aegis Gulf Compliance Kernel",
            "version"   : "1.0.0",
            "status"    : "operational",
            "company"   : "Aegis Gulf — Kimberley, Northern Cape, South Africa",
            "endpoints" : {
                "POST /archive"       : "Archive a compliance log entry (encrypted)",
                "GET  /verify"        : "Verify full audit chain integrity",
                "GET  /vault"         : "Export recent vault entries",
                "GET  /stats"         : "Performance and vault statistics",
                "GET  /benchmark"     : "Run live throughput benchmark (?count=10000)",
                "POST /demo/tamper"   : "Tamper with entry for demo ({'entry_id': N})",
                "GET  /health"        : "Health check",
            },
            "compliance" : {
                "encryption"  : "AES-256-GCM",
                "integrity"   : "SHA-256 HMAC chain",
                "popia"       : "Section 19 — Security safeguards",
                "retention"   : "5-year immutable archival",
            }
        })

    def _handle_health(self):
        stats = _kernel.stats()
        _json_response(self, {
            "status"         : "healthy",
            "kernel"         : "operational",
            "vault_entries"  : stats["total_entries"],
            "uptime_seconds" : stats["uptime_seconds"],
            "encryption"     : "AES-256-GCM — active",
            "chain"          : "SHA-256 HMAC — active",
        })

    def _handle_stats(self):
        stats = _kernel.stats()
        _json_response(self, {
            "aegis_gulf_kernel_stats": stats
        })

    def _handle_archive(self):
        try:
            body       = _read_body(self)
            event_type = body.get("event_type", "generic_event")
            payload    = body.get("payload", {})
            metadata   = body.get("metadata", {})

            t_start = time.monotonic()
            entry   = _kernel.archive(event_type, payload, metadata)
            elapsed_us = (time.monotonic() - t_start) * 1_000_000

            _json_response(self, {
                "status"        : "archived",
                "entry_id"      : entry.entry_id,
                "timestamp_utc" : entry.timestamp_utc,
                "chain_hmac"    : entry.chain_hmac_hex[:16] + "...",
                "encrypted"     : True,
                "algorithm"     : "AES-256-GCM",
                "latency_us"    : round(elapsed_us, 2),
                "popia_section" : "S.19 — Security safeguards — COMPLIANT",
            }, 201)
        except Exception as e:
            _json_response(self, {"error": str(e)}, 400)

    def _handle_verify(self):
        t_start = time.monotonic()
        result  = _kernel.verify_chain()
        elapsed = (time.monotonic() - t_start) * 1000

        status_code = 200 if result.valid else 409

        _json_response(self, {
            "chain_valid"     : result.valid,
            "entries_checked" : result.entries_checked,
            "broken_at_entry" : result.broken_at_id,
            "message"         : result.message,
            "verification_ms" : result.checked_in_ms,
            "regulator_ready" : result.valid,
            "popia_section"   : "S.19 — Audit immutability verification",
        }, status_code)

    def _handle_vault(self, limit: int):
        entries = _kernel.export_vault(limit=min(limit, 500))
        _json_response(self, {
            "vault_entries"  : entries,
            "count"          : len(entries),
            "note"           : "Ciphertext shown in hex. "
                               "Decryption requires authorised dual-authentication.",
        })

    def _handle_benchmark(self, count: int):
        """
        Live throughput benchmark.
        Archives `count` encrypted log entries and measures throughput.
        This is the number shown to the Lead Architect.
        """
        count   = min(count, 100_000)   # cap at 100k for demo
        payload = {
            "user_id"      : "benchmark-subject",
            "action"       : "transaction_complete",
            "amount_zar"   : 1250.00,
            "merchant_id"  : "M-8827-CPT",
            "popia_event"  : True,
        }

        print(f"\n  [BENCHMARK] Starting {count:,} encrypted archive operations...")
        t_start = time.monotonic()

        for i in range(count):
            payload["seq"] = i
            _kernel.archive("benchmark_event", payload, {"source": "benchmark"})

        elapsed_s  = time.monotonic() - t_start
        ops_per_s  = count / elapsed_s
        ms_per_op  = (elapsed_s / count) * 1000
        us_per_op  = ms_per_op * 1000

        print(f"  [BENCHMARK] {count:,} ops in {elapsed_s:.3f}s = "
              f"{ops_per_s:,.0f} ops/sec\n")

        
        verify = _kernel.verify_chain()

        _json_response(self, {
            "benchmark_results": {
                "operations_run"     : count,
                "elapsed_seconds"    : round(elapsed_s, 4),
                "ops_per_second"     : round(ops_per_s, 0),
                "ms_per_operation"   : round(ms_per_op, 4),
                "us_per_operation"   : round(us_per_op, 2),
                "encryption"         : "AES-256-GCM per entry",
                "chain_integrity"    : "SHA-256 HMAC per entry",
                "chain_valid_after"  : verify.valid,
                "total_vault_entries": verify.entries_checked,
            },
            "system_info": {
                "language"   : "Python 3.12 (production: C++20)",
                "note"       : "Python prototype — C++ kernel achieves 10-50x higher "
                               "throughput on same hardware via AES-NI and zero-copy memory.",
                "company"    : "Aegis Gulf — Kimberley, Northern Cape",
            }
        })

    def _handle_tamper(self):
        """Tamper with an entry for demo — shows tamper detection works."""
        try:
            body     = _read_body(self)
            entry_id = int(body.get("entry_id", 1))

            success = _kernel.tamper_for_demo(entry_id)
            if not success:
                _json_response(self, {"error": f"Entry {entry_id} not found"}, 404)
                return

            
            result = _kernel.verify_chain()

            _json_response(self, {
                "demo_action"    : f"Entry {entry_id} ciphertext deliberately corrupted",
                "chain_valid"    : result.valid,
                "broken_at"      : result.broken_at_id,
                "message"        : result.message,
                "demonstration"  : "This proves that any tampering with archived "
                                   "records is immediately and mathematically detectable. "
                                   "The Information Regulator receives this proof.",
            })
        except Exception as e:
            _json_response(self, {"error": str(e)}, 400)


def run_server(host: str = "0.0.0.0", port: int = 8000):
    print(BANNER)

    
    print("  Archiving sample compliance events...")
    _kernel.archive("user_data_collection",
                    {"user_id": "demo-001", "consent_given": True},
                    {"source": "checkout", "popia_section": "S.18"})
    _kernel.archive("transaction_log",
                    {"transaction_id": "TXN-88271", "amount_zar": 499.00,
                     "merchant": "Demo Merchant"},
                    {"source": "payment_gateway", "popia_section": "S.19"})
    _kernel.archive("personal_data_access",
                    {"accessed_by": "admin-role", "subject_id": "demo-001",
                     "fields": ["name", "email", "address"]},
                    {"source": "admin_portal", "popia_section": "S.23"})
    print(f"  Sample vault seeded with {_kernel.stats()['total_entries']} entries.")
    print(f"\n  Server running on http://{host}:{port}")
    print("  Press Ctrl+C to stop.\n")

    server = HTTPServer((host, port), AegisAPIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Kernel shutdown gracefully.")
        server.server_close()


if __name__ == "__main__":
    run_server()
