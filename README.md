# Log IDS

Simple log-based intrusion detection system (IDS) written in Python.

It reads log files (e.g. `/var/log/auth.log`, web server logs, etc.), detects common attack patterns, and generates a report showing suspicious IP addresses and counts.

**IMPORTANT:** Only use sample/test logs or logs you own. Do not share real customer data.

## Patterns detected
- SSH brute force: failed password attempts
- Web attack patterns (basic): common 404 probes and SQLi/XSS-like strings
- Port scan heuristic: many different ports from the same IP

## Usage

Clone the repo and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # optional, may be empty

python3 ids.py --log sample_log.txt
# or
python3 ids.py --log /var/log/auth.log
```

Outputs `ids_report.md` with a summary.
