import subprocess
import ssl
import time

def read_certificate_details(certificate_path):
    result = subprocess.run(
        ["openssl", "x509", "-in", certificate_path, "-noout", "-issuer", "-enddate"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()

def days_until_expiry(certificate_path):
    details = read_certificate_details(certificate_path)

    for line in details.splitlines():
        if line.startswith("notAfter="):
            expiry_text = line.split("=", 1)[1]
            expiry_seconds = ssl.cert_time_to_seconds(expiry_text)
            return int((expiry_seconds - time.time()) // 86400)

    raise ValueError("Missing certificate expiration date")


def verify_certificate(certificate_path):
    result = subprocess.run(
        ["openssl", "verify", certificate_path],
        capture_output=True,
        text=True
    )
    return "Valid" if result.returncode == 0 else "Invalid"

def audit_local_certificate(certificate_path):
    details = read_certificate_details(certificate_path)

    issuer = details.splitlines()[0].split("=", 1)[1].strip()
    expiry_date = details.splitlines()[1].split("=", 1)[1].strip()
    days_remaining = days_until_expiry(certificate_path)
    is_valid = verify_certificate(certificate_path)

    return issuer, expiry_date, days_remaining, is_valid