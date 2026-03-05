import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

IP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

PATTERNS = {
    "ssh_bruteforce": re.compile(r"(Failed password|Invalid user|authentication failure)", re.I),
    "ssh_success_after_fail": re.compile(r"Accepted password", re.I),
    "web_xss": re.compile(r"(<script|javascript:|onerror=)", re.I),
    "web_sqli": re.compile(r"(union select|or 1=1|information_schema)", re.I),
    "web_scan": re.compile(r"(wp-admin|phpmyadmin|/cgi-bin|/etc/passwd|phpinfo|wp-login)", re.I),
    "web_rfi_lfi": re.compile(r"(\?cmd=|\?execute=|../../|..\\..\\)", re.I),
    "port_scan": re.compile(r"(Nmap|Masscan)", re.I),
}

def extract_ip(line: str) -> str:
    m = IP_REGEX.search(line)
    return m.group(1) if m else "-"


def main() -> None:
    ap = argparse.ArgumentParser(description="Log-based intrusion detection (IDS)")
    ap.add_argument("--log", required=True, help="Path to log file (auth log, web access log, etc.)")
    ap.add_argument("--out", default="ids_report.md", help="Output markdown report")
    args = ap.parse_args()

    counters: dict[str, Counter] = defaultdict(Counter)
    totals: Counter = Counter()

    log_path = Path(args.log)
    if not log_path.exists():
        raise SystemExit(f"Log file not found: {log_path}")

    with open(log_path, "r", errors="ignore") as f:
        for line in f:
            for name, regex in PATTERNS.items():
                if regex.search(line):
                    ip = extract_ip(line)
                    counters[name][ip] += 1
                    totals[ip] += 1

    out_lines: list[str] = []
    out_lines.append("# Log IDS Report\n\n")
    out_lines.append(f"**Log file:** `{log_path.name}`\n\n")
    out_lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

    out_lines.append("## Patterns searched\n")
    for name in PATTERNS.keys():
        out_lines.append(f"- {name}\n")
    out_lines.append("\n")

    out_lines.append("## Top suspicious IPs (all patterns)\n\n")
    if totals:
        out_lines.append("| IP | Count |\n|---|---:|\n")
        for ip, count in totals.most_common(10):
            out_lines.append(f"| {ip} | {count} |\n")
        out_lines.append("\n")
    else:
        out_lines.append("No suspicious patterns found in this log.\n\n")

    for name, ctr in counters.items():
        out_lines.append(f"## {name}\n\n")
        if ctr:
            out_lines.append("| IP | Count |\n|---|---:|\n")
            for ip, count in ctr.most_common(10):
                out_lines.append(f"| {ip} | {count} |\n")
            out_lines.append("\n")
        else:
            out_lines.append("No matches found.\n\n")

    out_lines.append("## Notes\n")
    out_lines.append("- This is a simple pattern-based IDS; tune patterns and thresholds for your environment.\n")
    out_lines.append("- Only analyze logs you own or are authorized to review.\n")

    Path(args.out).write_text("".join(out_lines), encoding="utf-8")
    print(f"Report written: {args.out}")


if __name__ == "__main__":
    main()
