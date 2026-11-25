import subprocess
import re

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
WEAK_CIPHER_KEYWORDS = ["RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "CBC_SHA"]
DEFAULT_TLS_PORTS = "443,8443,465,993,995"

def discover_tls_ports(host: str, ports: str = DEFAULT_TLS_PORTS, timeout: int = 30) -> list:
    """
    Discovers open TLS/SSL ports on a target host using Nmap.
    Returns a list of open port numbers (integers).
    """
    cmd = ["nmap", "-Pn", "-n", "-p", ports, "--open", host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return [int(m) for m in re.findall(r"(\d+)/tcp\s+open", proc.stdout)]
    except Exception:
        return []

def scan_tls_ciphers(host: str, port: int = 443, timeout: int = 60) -> dict:
    """
    Runs Nmap's ssl-enum-ciphers NSE script against a target host and port.
    Returns a dictionary with detected weak protocols, weak ciphers, and scan status.
    """
    cmd = ["nmap", "-Pn", "-n", "-p", str(port), "--script", "ssl-enum-ciphers", host]
    result = {
        "host": host,
        "port": port,
        "weak_protocols": "None",
        "weak_ciphers": "None",
        "status": "OK"
    }

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout

        if proc.returncode != 0 or not output:
            result["status"] = "Nmap Error"
            return result

        found_protocols = []
        for proto in WEAK_PROTOCOLS:
            if re.search(rf"\b{re.escape(proto)}\s*:", output):
                found_protocols.append(proto)

        found_ciphers = []
        for line in output.splitlines():
            clean_line = line.strip()
            if clean_line.startswith("|") and any(kw in clean_line for kw in WEAK_CIPHER_KEYWORDS):
                parts = clean_line.lstrip("|_ ").split()
                if parts and ("TLS_" in parts[0] or "SSL_" in parts[0]):
                    found_ciphers.append(parts[0])

        if found_protocols:
            result["weak_protocols"] = ", ".join(found_protocols)
        if found_ciphers:
            unique_ciphers = sorted(list(set(found_ciphers)))
            result["weak_ciphers"] = ", ".join(unique_ciphers[:3])

    except subprocess.TimeoutExpired:
        result["status"] = "Timeout"
    except FileNotFoundError:
        result["status"] = "Nmap Not Installed"
    except Exception as e:
        result["status"] = f"Error: {str(e)}"

    return result


if __name__ == "__main__":
    test_hosts = [
        "badssl.com",
        "rc4.badssl.com",
        "3des.badssl.com",
    ]

    print("[*] Testing auto port discovery + cipher scan...\n")
    for target_host in test_hosts:
        open_ports = discover_tls_ports(target_host)
        print(f"Host: {target_host} | Open TLS Ports: {open_ports}")
        for port in open_ports:
            res = scan_tls_ciphers(target_host, port)
            print(f"  [{res['host']}:{res['port']}]")
            print(f"    -> Weak Protocols : {res['weak_protocols']}")
            print(f"    -> Weak Ciphers   : {res['weak_ciphers']}")
            print(f"    -> Status         : {res['status']}\n")
