import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from db_manager import init_db, insert_result
from nmap_scanner import discover_tls_ports, scan_tls_ciphers
from openssl_auditor import audit_with_openssl

BASE_DIR = Path(__file__).resolve().parent
TARGETS_FILE = BASE_DIR / "targets.txt"


Target = Tuple[str, Optional[int]]


def load_targets(file_path: Path = TARGETS_FILE) -> List[Target]:
    """Read targets in host:port or host format, ignoring blank/comment lines."""
    targets: List[Target] = []

    if not file_path.is_file():
        raise FileNotFoundError(f"Targets file was not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as target_file:
        for line_number, raw_line in enumerate(target_file, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue

            if ":" in line:
                host, port_text = line.rsplit(":", 1)
                host = host.strip()
                try:
                    port = int(port_text.strip())
                except ValueError as exc:
                    raise ValueError(
                        f"Invalid port on line {line_number}: {raw_line.strip()}"
                    ) from exc
                if not 1 <= port <= 65535:
                    raise ValueError(
                        f"Port must be between 1 and 65535 on line {line_number}."
                    )
                targets.append((host, port))
            else:
                targets.append((line, None))

    return targets


def classify_status(
    days_remaining: int,
    is_valid: str,
    weak_protocols: str,
    weak_ciphers: str,
    nmap_status: str = "OK",
) -> str:
    """Apply the severity priority described in the Phase 2 team plan."""
    validity = (is_valid or "").strip()

    # -999 is the sentinel used by the OpenSSL auditor for an unavailable
    # certificate/connection. It must not be mistaken for an expired cert.
    if validity.startswith("Invalid") or (
        days_remaining < 0 and days_remaining != -999
    ):
        return "CRITICAL: Invalid/Expired"

    if weak_protocols != "None" or weak_ciphers != "None":
        return "WARNING: Weak TLS/Cipher"

    if days_remaining != -999 and 0 <= days_remaining <= 30:
        return "WARNING: Expiring Soon"

    # Do not label a host HEALTHY when either audit failed or returned
    # incomplete data.
    if validity != "Valid" or days_remaining == -999 or nmap_status != "OK":
        return "WARNING: Audit Incomplete"

    return "HEALTHY"


def _store_unscanned_target(host: str, reason: str) -> None:
    """Store a visible record when port discovery finds no TLS service."""
    scan_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    insert_result(
        (
            scan_time,
            host,
            None,
            "Unknown",
            "N/A",
            -999,
            f"Connection Failed: {reason}",
            "Not Scanned",
            "Not Scanned",
            "WARNING: Audit Incomplete",
            0.0,
        )
    )
    print(f"{host:<28} | {'N/A':<5} | {'Not scanned':<22} | {'N/A':<12} | {0.0:<6} | WARNING: Audit Incomplete")


def scan_target(host: str, port: int) -> None:
    """Run both audits for one host/port, classify the result, and store it."""
    start_time = time.perf_counter()

    try:
        issuer, expiry_date, days_remaining, is_valid = audit_with_openssl(
            host, port
        )
    except Exception as exc:
        issuer = "Unknown"
        expiry_date = "N/A"
        days_remaining = -999
        is_valid = f"Connection Failed: {exc}"

    try:
        nmap_result = scan_tls_ciphers(host, port)
        weak_protocols = nmap_result.get("weak_protocols", "None")
        weak_ciphers = nmap_result.get("weak_ciphers", "None")
        nmap_status = nmap_result.get("status", "Unknown")
    except Exception as exc:
        weak_protocols = "None"
        weak_ciphers = "None"
        nmap_status = f"Error: {exc}"

    duration = round(time.perf_counter() - start_time, 2)
    status = classify_status(
        days_remaining,
        is_valid,
        weak_protocols,
        weak_ciphers,
        nmap_status,
    )
    scan_time = datetime.now(timezone.utc).isoformat(timespec="seconds")

    insert_result(
        (
            scan_time,
            host,
            port,
            issuer,
            expiry_date,
            days_remaining,
            is_valid,
            weak_protocols,
            weak_ciphers,
            status,
            duration,
        )
    )

    print(
        f"{host:<28} | {days_remaining:<5} | {is_valid[:22]:<22} | "
        f"{weak_protocols[:12]:<12} | {duration:<6} | {status}"
    )


def run_certiwatch() -> None:
    """Run one complete scan cycle for all configured targets."""
    init_db()
    targets = load_targets()

    print(f"[*] Starting CertiWatch scan for {len(targets)} target(s)...\n")
    print(
        f"{'TARGET':<28} | {'DAYS':<5} | {'VALIDITY':<22} | "
        f"{'WEAK TLS':<12} | {'TIME':<6} | STATUS"
    )
    print("-" * 120)

    total_start = time.perf_counter()

    for host, configured_port in targets:
        if configured_port is not None:
            ports = [configured_port]
        else:
            try:
                ports = discover_tls_ports(host)
            except Exception:
                ports = []

        if not ports:
            _store_unscanned_target(host, "No open TLS port discovered")
            continue

        for port in ports:
            scan_target(host, port)

    total_duration = round(time.perf_counter() - total_start, 2)
    print("\n[+] Scan cycle complete. Results saved to certiwatch.db")
    print(f"[+] Total scan time: {total_duration:.2f} seconds")


if __name__ == "__main__":
    run_certiwatch()
