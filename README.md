# CertiWatch
Automated Secure Service Certificate Monitoring Framework using Python, Nmap, OpenSSL, SQLite, and Grafana.

## Project Structure
- `nmap_scanner.py` — TLS protocol & weak cipher enumeration (Abdallah)
- `openssl_auditor.py` — X.509 certificate verification & expiration check (Randa)
- `db_manager.py` & `main.py` — SQLite storage, risk classification & scheduling (Sarah)
- `targets.txt` — Authorized `badssl.com` test domains
- `grafana/` — Dashboard JSON & Alert Rules (Yousef)
