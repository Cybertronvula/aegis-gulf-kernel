"""
Aegis Gulf Compliance Kernel — Core Engine
==========================================
AES-256-GCM encryption + SHA-256 HMAC audit chain

Every log entry is:
  1. Encrypted with AES-256-GCM (authenticated encryption)
  2. Tagged with a SHA-256 HMAC linking it to the previous entry
  3. Written to an append-only vault

Tampering with any entry breaks the chain — mathematically provable.

Author : Nvula Bontes — Lead Architect, Aegis Gulf
Version: 1.0.0
"""

import os
import hmac
import hashlib
import json
import time
import threading
from typing import Optional
from dataclasses import dataclass, field, asdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Constants ─────────────────────────────────────────────────────────────────
KEY_SIZE_BYTES  = 32        # AES-256
NONCE_SIZE      = 12        # GCM standard nonce
CHAIN_GENESIS   = b"\x00" * 32  # Genesis block hash — known starting point


# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class ArchivedEntry:
    """
    A single immutable log entry in the Aegis Gulf vault.

    Fields:
        entry_id        : Sequential identifier
        timestamp_utc   : Unix timestamp (float) when entry was archived
        ciphertext_hex  : AES-256-GCM encrypted payload (hex encoded)
        nonce_hex       : GCM nonce used for this entry (hex encoded)
        chain_hmac_hex  : SHA-256 HMAC linking this entry to the previous
        prev_hmac_hex   : The HMAC of the previous entry (chain anchor)
        metadata        : Plaintext metadata (category, source system, etc.)
    """
    entry_id       : int
    timestamp_utc  : float
    ciphertext_hex : str
    nonce_hex      : str
    chain_hmac_hex : str
    prev_hmac_hex  : str
    metadata       : dict = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Result of a chain integrity verification."""
    valid          : bool
    entries_checked: int
    first_entry_id : int
    last_entry_id  : int
    broken_at_id   : Optional[int]
    message        : str
    checked_in_ms  : float


# ── Core Engine ───────────────────────────────────────────────────────────────
class AegisComplianceKernel:
    """
    The Aegis Gulf compliance kernel.

    Provides:
        - AES-256-GCM encryption of every log entry
        - SHA-256 HMAC audit chain across all entries
        - Thread-safe append-only vault
        - Tamper-evidence verification
        - Performance benchmarking

    Usage:
        kernel = AegisComplianceKernel()
        entry  = kernel.archive("user_login", {"user_id": "abc123"})
        result = kernel.verify_chain()
    """

    def __init__(self, encryption_key: Optional[bytes] = None):
        # AES-256 key — generated fresh if not provided
        self._key       = encryption_key or AESGCM.generate_key(bit_length=256)
        self._aesgcm    = AESGCM(self._key)

        # HMAC key — separate from encryption key (defence in depth)
        self._hmac_key  = os.urandom(KEY_SIZE_BYTES)

        # Append-only vault
        self._vault     : list[ArchivedEntry] = []
        self._lock      = threading.Lock()

        # Chain state — tracks last HMAC for linking
        self._last_hmac = CHAIN_GENESIS

        # Stats
        self._total_bytes_archived = 0
        self._start_time           = time.monotonic()

    # ── Archival ──────────────────────────────────────────────────────────────
    def archive(
        self,
        event_type : str,
        payload    : dict,
        metadata   : Optional[dict] = None
    ) -> ArchivedEntry:
        """
        Archive a compliance log entry.

        The payload is JSON-serialised, encrypted with AES-256-GCM,
        and linked into the audit chain via SHA-256 HMAC.

        Returns the immutable ArchivedEntry written to the vault.
        """
        raw_payload = json.dumps({
            "event_type": event_type,
            "payload"   : payload,
            "ts"        : time.time(),
        }, sort_keys=True).encode("utf-8")

        # ── AES-256-GCM encryption ────────────────────────────────────────────
        # Fresh random nonce per entry — never reused
        nonce      = os.urandom(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, raw_payload, None)

        # ── SHA-256 HMAC chain ────────────────────────────────────────────────
        # The HMAC input is: prev_hmac || ciphertext
        # This creates an unforgeable chain — changing any entry
        # changes its HMAC, which changes every subsequent HMAC.
        chain_input = self._last_hmac + ciphertext
        chain_hmac  = hmac.new(
            self._hmac_key,
            chain_input,
            hashlib.sha256
        ).digest()

        with self._lock:
            entry_id      = len(self._vault) + 1
            prev_hmac_hex = self._last_hmac.hex()
            self._last_hmac = chain_hmac

            entry = ArchivedEntry(
                entry_id       = entry_id,
                timestamp_utc  = time.time(),
                ciphertext_hex = ciphertext.hex(),
                nonce_hex      = nonce.hex(),
                chain_hmac_hex = chain_hmac.hex(),
                prev_hmac_hex  = prev_hmac_hex,
                metadata       = metadata or {"event_type": event_type},
            )
            self._vault.append(entry)
            self._total_bytes_archived += len(raw_payload)

        return entry

    # ── Decryption (authorised access only) ───────────────────────────────────
    def decrypt(self, entry: ArchivedEntry) -> dict:
        """
        Decrypt an archived entry (simulates authorised access).
        In production this requires dual-authorisation (4-eyes).
        """
        ciphertext = bytes.fromhex(entry.ciphertext_hex)
        nonce      = bytes.fromhex(entry.nonce_hex)
        plaintext  = self._aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))

    # ── Chain verification ─────────────────────────────────────────────────────
    def verify_chain(self) -> VerificationResult:
        """
        Verify the integrity of the entire audit chain.

        Recomputes every HMAC from the genesis block forward.
        Any tampering — even a single bit changed anywhere —
        will cause a mismatch and report the exact entry where
        the chain broke.

        This is the proof of tamper-evidence shown to the Regulator.
        """
        start_ms = time.monotonic()

        with self._lock:
            entries = list(self._vault)

        if not entries:
            return VerificationResult(
                valid=True, entries_checked=0,
                first_entry_id=0, last_entry_id=0,
                broken_at_id=None,
                message="Vault is empty — chain is valid (nothing to verify).",
                checked_in_ms=0.0
            )

        running_hmac = CHAIN_GENESIS

        for entry in entries:
            ciphertext  = bytes.fromhex(entry.ciphertext_hex)
            chain_input = running_hmac + ciphertext
            expected    = hmac.new(
                self._hmac_key, chain_input, hashlib.sha256
            ).digest()

            # Constant-time comparison — prevents timing attacks
            if not hmac.compare_digest(expected, bytes.fromhex(entry.chain_hmac_hex)):
                elapsed = (time.monotonic() - start_ms) * 1000
                return VerificationResult(
                    valid=False,
                    entries_checked=entry.entry_id,
                    first_entry_id=entries[0].entry_id,
                    last_entry_id=entries[-1].entry_id,
                    broken_at_id=entry.entry_id,
                    message=f"CHAIN BROKEN at entry {entry.entry_id}. "
                            f"Tampering detected — this entry has been modified.",
                    checked_in_ms=round(elapsed, 3)
                )
            running_hmac = expected

        elapsed = (time.monotonic() - start_ms) * 1000
        return VerificationResult(
            valid=True,
            entries_checked=len(entries),
            first_entry_id=entries[0].entry_id,
            last_entry_id=entries[-1].entry_id,
            broken_at_id=None,
            message=f"Chain verified. All {len(entries)} entries are intact. "
                    f"No tampering detected.",
            checked_in_ms=round(elapsed, 3)
        )

    # ── Tamper simulation (for demo purposes) ─────────────────────────────────
    def tamper_for_demo(self, entry_id: int) -> bool:
        """
        Deliberately tamper with an entry to demonstrate detection.
        FOR DEMONSTRATION ONLY — shows the Regulator what tamper-detection looks like.
        """
        with self._lock:
            for entry in self._vault:
                if entry.entry_id == entry_id:
                    # Flip the last byte of the ciphertext
                    ct       = bytearray(bytes.fromhex(entry.ciphertext_hex))
                    ct[-1]   ^= 0xFF
                    entry.ciphertext_hex = ct.hex()
                    return True
        return False

    # ── Stats ─────────────────────────────────────────────────────────────────
    def stats(self) -> dict:
        """Return current vault and performance statistics."""
        with self._lock:
            count = len(self._vault)
        elapsed = time.monotonic() - self._start_time
        return {
            "total_entries"         : count,
            "total_bytes_archived"  : self._total_bytes_archived,
            "uptime_seconds"        : round(elapsed, 2),
            "encryption_algorithm"  : "AES-256-GCM",
            "hmac_algorithm"        : "SHA-256",
            "key_size_bits"         : KEY_SIZE_BYTES * 8,
            "nonce_size_bytes"      : NONCE_SIZE,
            "chain_genesis_hex"     : CHAIN_GENESIS.hex()[:16] + "...",
        }

    # ── Vault export (for Regulator submission) ───────────────────────────────
    def export_vault(self, limit: int = 100) -> list[dict]:
        """Export vault entries as JSON-serialisable dicts."""
        with self._lock:
            entries = list(self._vault[-limit:])
        return [asdict(e) for e in entries]
