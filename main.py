import time
from datetime import datetime, timezone
from db_manager import init_db, insert_result
from nmap_scanner import scan_tls_ciphers
from openssl_auditor import audit_with_openssl

TARGETS_FILE = "targets.txt"


def classify_status(days_remaining, is_valid, weak_protocols, weak_ciphers):
    if "Invalid" in is_valid or days_remaining < 0:
        return "CRITICAL: Invalid/Expired"
    if weak_protocols != "None" or weak_ciphers != "None":
        return "WARNING: Weak TLS/Cipher"
    if days_remaining <= 30:
        return "WARNING: Expiring Soon"
    return "HEALTHY"


def run_certiwatch():
    init_db()

    with open(TARGETS_FILE, "r") as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"[*] Starting CertiWatch Scan on {len(targets)} targets...\n")
    print(f"{'TARGET':<28} | {'DAYS':<5} | {'VALIDITY':<22} | {'WEAK TLS':<12} | {'TIME':<6} | STATUS")
    print("-" * 114)

    for item in targets:
        host, port = item.split(":")
        port = int(port)
        start_time = time.time()

        issuer, expiry_date, days_remaining, is_valid = audit_with_openssl(host, port)
        nmap_res = scan_tls_ciphers(host, port)
        weak_protocols = nmap_res["weak_protocols"]
        weak_ciphers = nmap_res["weak_ciphers"]

        status = classify_status(days_remaining, is_valid, weak_protocols, weak_ciphers)
        duration = round(time.time() - start_time, 2)
        scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        insert_result((
            scan_time, host, port, issuer, expiry_date, days_remaining,
            is_valid, weak_protocols, weak_ciphers, status, duration
        ))

        print(f"{host:<28} | {days_remaining:<5} | {is_valid[:22]:<22} | {weak_protocols:<12} | {duration:<6} | {status}")

    print("\n[+] Scan complete! Results saved to certiwatch.db")


if __name__ == "__main__":
    run_certiwatch()
