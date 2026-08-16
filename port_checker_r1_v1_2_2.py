#!/usr/bin/env python3
"""
Ruckus One readiness and regional response checker using Python built-in libraries only.

Run with --version to print the current tool version (see the VERSION constant
below, the single source of truth) rather than relying on this docstring, which
is not updated per release.

Adds optional append-only history logging for long-term graphing:
    --history-file r1_history.csv

Can fetch its target list from an ingest service instead of a local
file, caching the result and falling back to the cache on failure:
    --targets-url https://your-service.up.railway.app/targets

Normal use (replace SCRIPT with this file's actual name):
    python3 SCRIPT
    python3 SCRIPT --history-file r1_history.csv
    python3 SCRIPT -f customer_hosts.csv --history-file customer_history.csv

The -i option is intentionally unused and reserved for future interface selection.
"""

import argparse
import csv
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError

VERSION = "1.2.4"
DEFAULT_FILE = "hosts_r1.csv"
DEFAULT_TIMEOUT = 5.0
DEFAULT_WORKERS = 1  # serial by default -- one connection at a time, not a burst
DEFAULT_CERT_WARNING_DAYS = 30
DEFAULT_CONFIG_FILE = "port_checker_r1_config.json"
DEFAULT_TARGETS_CACHE_HOURS = 24.0

# Built-in fallback for every config-file/CLI-overridable option. No passwords or
# secrets belong in the config file, only these plain operational settings.
CONFIG_DEFAULTS = {
    "org": None,
    "file": DEFAULT_FILE,
    "output_csv": "r1_port_check_results.csv",
    "output_json": "r1_port_check_results.json",
    "history_file": None,
    "timeout": DEFAULT_TIMEOUT,
    "workers": DEFAULT_WORKERS,
    "tls_all": False,
    "udp_strict": False,
    "cert_warning_days": DEFAULT_CERT_WARNING_DAYS,
    "no_archive": False,
    "skip_public_ip": False,
    "targets_url": None,
    "targets_cache_hours": DEFAULT_TARGETS_CACHE_HOURS,
}
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"
UDP_DEFAULT_PORTS = {1812, 1813}
KNOWN_ZONES = {"GLOBAL", "US", "EU", "APAC", "ASIA"}
READINESS_ZONES = ["GLOBAL", "US", "EU", "APAC"]
R1_ZONES = ["US", "EU", "APAC"]

RESULT_FIELDS = [
    "timestamp_utc", "zone", "service_pass", "service_pass_reason",
    "response_ms", "response_basis",
    "status", "host", "port", "protocol", "description",
    "dns_status", "dns_ip", "dns_all_ips", "dns_ms",
    "tcp_status", "tcp_ms", "udp_status", "udp_ms",
    "tls_status", "tls_ms", "cert_valid", "cert_status",
    "cert_not_before", "cert_not_after", "cert_days_since_start",
    "cert_days_remaining", "cert_total_days", "cert_subject", "cert_issuer",
    "error",
]

HISTORY_FIELDS = [
    "run_timestamp_utc", "tool_version", "input_file", "zone", "status",
    "global_status", "regional_status", "passed", "total", "failed",
    "regional_median_ms", "regional_avg_ms", "effective_median_ms", "effective_avg_ms",
    "fastest_passing_zone", "is_fastest_passing_zone",
]

STATUS_PRIORITY = {
    "DNS_FAIL": 10,
    "TCP_TIMEOUT": 20,
    "TCP_FAIL": 30,
    "TLS_FAIL": 40,
    "CERT_INVALID": 50,
    "CERT_NOT_YET_VALID": 55,
    "CERT_EXPIRED": 60,
    "CERT_EXPIRING_SOON": 70,
    "UDP_UNREACHABLE": 80,
    "UDP_NO_RESPONSE": 90,
    "CHECK_ERROR": 100,
    "UNSUPPORTED_PROTOCOL": 900,
    "OK": 999,
}


def get_local_ip():
    """Determine this machine's local network IP address.

    Opens a throwaway UDP socket to a public address (no packets are actually
    sent) so the OS reports the outbound interface IP. Used to tag JSON output
    with the source location since this script can run from many hosts.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return ""


def get_public_ip(timeout=3.0):
    """Look up the outside NAT IP address via an external HTTP service.

    Tries a small list of plain-text IP echo services and returns the first
    successful response. Used to tag JSON output with the public-facing IP so
    results collected from different sites/NATs can be told apart.
    """
    services = (
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
    )
    for url in services:
        try:
            with urlopen(url, timeout=timeout) as response:
                ip = response.read().decode().strip()
                if ip:
                    return ip
        except (URLError, OSError, ValueError):
            continue
    return ""


def get_source_info(skip_public_ip=False):
    """Collect hostname, local IP, and public IP describing where this run executed.

    Used to populate JSON metadata so results from different locations/NATs are
    distinguishable when consolidating output later.
    """
    return {
        "hostname": socket.gethostname(),
        "local_ip": get_local_ip(),
        "public_ip": "" if skip_public_ip else get_public_ip(),
    }


def utc_now_iso():
    """Return the current UTC time as an ISO string.

    Used for per-result timestamps, run metadata, archive filenames, and history
    rows so every output generated by one run can be correlated later.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_zone(value):
    """Normalize user-facing zone labels to GLOBAL, US, EU, or APAC.

    Used by the hosts-file parser and reporting logic. It maps ASIA to APAC and
    safely defaults unknown or blank values to GLOBAL.
    """
    value = (value or "GLOBAL").strip().upper()
    if value == "ASIA":
        return "APAC"
    if value in READINESS_ZONES:
        return value
    return "GLOBAL"


def parse_zone_heading(line):
    """Return the zone named by a markdown-style heading, if present.

    Used while parsing hosts_r1.csv. Headings such as '# GLOBAL', '## EU', and
    '# APAC' set the current zone for following rows.
    """
    stripped = line.strip()
    if not stripped.startswith("#"):
        return None
    text = stripped.lstrip("#").strip()
    if not text:
        return None
    first = text.split()[0].upper()
    if first in KNOWN_ZONES:
        return normalize_zone(first)
    return None


def safe_float(value):
    """Convert a value to float or return None for blanks/non-numeric values.

    Used by the response timing summary functions so missing measurements do not
    break average and median calculations.
    """
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def rounded(value, digits=2):
    """Round numeric output values while preserving blanks.

    Used for readable timing values in console output, CSV, JSON, and history.
    """
    if value is None:
        return ""
    return round(float(value), digits)


def empty_result(host, port, protocol, zone="GLOBAL", description=""):
    """Create a complete result row with all expected output fields.

    Used at the start of each check and when an unexpected error occurs. A fixed
    template keeps CSV and JSON output consistent regardless of failure point.
    """
    return {
        "timestamp_utc": utc_now_iso(),
        "zone": normalize_zone(zone),
        "service_pass": False,
        "service_pass_reason": "NOT_EVALUATED",
        "response_ms": "",
        "response_basis": "NOT_EVALUATED",
        "status": "UNKNOWN",
        "host": host,
        "port": int(port),
        "protocol": protocol.upper(),
        "description": description,
        "dns_status": "NOT_CHECKED",
        "dns_ip": "",
        "dns_all_ips": "",
        "dns_ms": "",
        "tcp_status": "NOT_CHECKED",
        "tcp_ms": "",
        "udp_status": "NOT_CHECKED",
        "udp_ms": "",
        "tls_status": "NOT_CHECKED",
        "tls_ms": "",
        "cert_valid": "",
        "cert_status": "NOT_CHECKED",
        "cert_not_before": "",
        "cert_not_after": "",
        "cert_days_since_start": "",
        "cert_days_remaining": "",
        "cert_total_days": "",
        "cert_subject": "",
        "cert_issuer": "",
        "error": "",
    }


def infer_port_from_scheme(scheme):
    """Infer a port number from a URL scheme.

    Used when users paste URLs into the hosts file instead of host,port rows.
    """
    scheme = (scheme or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def strip_url_to_host_port(value):
    """Extract host and optional port from URL, host:port, or hostname text.

    Used by parse_hosts_file so endpoint lists copied from documentation remain
    usable without manual cleanup.
    """
    value = value.strip()
    if not value:
        return "", None
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.hostname or "", parsed.port or infer_port_from_scheme(parsed.scheme)
    if value.count(":") == 1:
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            return host_part.strip(), int(port_part)
    return value, None


def normalize_protocol(protocol, port):
    """Return the protocol for a target, inferring defaults when omitted.

    TCP is used by default, except ports 1812 and 1813 which default to UDP for
    the Ruckus One RADIUS proxy use case.
    """
    if protocol:
        return protocol.strip().upper()
    if int(port) in UDP_DEFAULT_PORTS:
        return "UDP"
    return "TCP"


def is_header_row(fields):
    """Detect CSV header rows and prevent them being treated as targets.

    Used to allow optional headings such as host,port,protocol in hosts files.
    """
    normalized = [f.strip().lower() for f in fields]
    return bool(normalized and normalized[0] in {"host", "hostname", "fqdn", "url"})


def cache_is_fresh(path, max_age_hours):
    """Return True if path exists and was modified within max_age_hours.

    Used by resolve_targets_file to decide whether a re-fetch is needed.
    """
    path = Path(path)
    if not path.exists():
        return False
    age_seconds = time.time() - path.stat().st_mtime
    return age_seconds < max_age_hours * 3600


def fetch_targets_text(url, timeout=10.0):
    """Download the target list from an ingest service as raw text.

    Used by resolve_targets_file. Raises URLError/OSError on failure so
    the caller can decide whether to fall back to a cached copy.
    """
    with urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8")


def resolve_targets_file(path, targets_url, cache_hours):
    """Ensure the hosts file at path is present and reasonably fresh.

    Used by main before parsing the hosts file. A no-op (always returns
    True) when targets_url is not set, so the script behaves exactly as
    it did before target-list fetching existed. Otherwise: a fresh
    cache is reused as-is; a missing or stale cache triggers a fetch;
    a failed fetch falls back to a stale cache with a warning, and only
    fails outright when there is no cache to fall back on.
    """
    if not targets_url:
        return True

    path = Path(path)
    if cache_is_fresh(path, cache_hours):
        return True

    try:
        text = fetch_targets_text(targets_url)
    except (URLError, OSError) as exc:
        if path.exists():
            print(
                f"WARNING: could not refresh target list from {targets_url} "
                f"({exc}); using cached copy from {path}",
                file=sys.stderr,
            )
            return True
        print(
            f"ERROR: could not fetch target list from {targets_url} and no "
            f"cached copy exists at {path}: {exc}",
            file=sys.stderr,
        )
        return False

    path.write_text(text, encoding="utf-8")
    print(f"Fetched target list from {targets_url} -> {path}")
    return True


def parse_hosts_file(path):
    """Parse the hosts file into target dictionaries for worker threads.

    Handles markdown zone headings, comments, blank lines, URLs, host:port text,
    and CSV rows. This is where the human-friendly endpoint list becomes the
    structured input used by the checker.
    """
    targets = []
    path = Path(path)
    current_zone = "GLOBAL"

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            heading_zone = parse_zone_heading(line)
            if heading_zone:
                current_zone = heading_zone
                continue
            if line.startswith("#"):
                continue
            if " #" in line:
                line = line.split(" #", 1)[0].strip()

            try:
                fields = next(csv.reader([line]))
            except csv.Error as exc:
                print(f"Skipping line {line_number}: CSV parse error: {exc}", file=sys.stderr)
                continue

            fields = [f.strip() for f in fields]
            if not fields or is_header_row(fields):
                continue

            host = ""
            port = None
            protocol = ""
            description = ""
            explicit_zone = ""

            if len(fields) == 1:
                host, port = strip_url_to_host_port(fields[0])
                if port is None:
                    port = 443
            else:
                host, inferred_port = strip_url_to_host_port(fields[0])
                port_text = fields[1] if len(fields) > 1 else ""
                if port_text:
                    try:
                        port = int(port_text)
                    except ValueError:
                        port = inferred_port or 443
                        protocol = port_text
                else:
                    port = inferred_port or 443
                if len(fields) > 2:
                    protocol = fields[2]
                if len(fields) > 3:
                    description = fields[3]
                if len(fields) > 4:
                    explicit_zone = fields[4]

            if not host:
                print(f"Skipping line {line_number}: empty host", file=sys.stderr)
                continue
            try:
                port = int(port)
                if port < 1 or port > 65535:
                    raise ValueError("port out of range")
            except (TypeError, ValueError):
                print(f"Skipping line {line_number}: invalid port '{port}'", file=sys.stderr)
                continue

            targets.append({
                "host": host,
                "port": port,
                "protocol": normalize_protocol(protocol, port),
                "description": description,
                "zone": normalize_zone(explicit_zone or current_zone),
                "source_line": line_number,
            })
    return targets


def resolve_dns(host, result):
    """Resolve hostname and capture DNS status, IPs, and lookup time.

    Used as the first check stage for every protocol because all R1 readiness
    checks depend on DNS. DNS timing also contributes to response_ms.
    """
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        result["dns_status"] = "OK"
        result["dns_ip"] = ips[0] if ips else ""
        result["dns_all_ips"] = ";".join(ips)
        result["dns_ms"] = rounded((time.perf_counter() - start) * 1000)
        return ips
    except (socket.gaierror, OSError) as exc:
        result["dns_status"] = "FAIL"
        result["dns_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["status"] = "DNS_FAIL"
        result["error"] = str(exc)
        return []


def tcp_connect(host, port, timeout, result):
    """Attempt TCP connection and capture connection timing.

    Used for HTTP, HTTPS, SSH, and other TCP services. TCP OPEN is required for
    TCP service readiness.
    """
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result["tcp_status"] = "OPEN"
        result["tcp_ms"] = rounded((time.perf_counter() - start) * 1000)
        return sock
    except socket.timeout as exc:
        result["tcp_status"] = "TIMEOUT"
        result["tcp_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["status"] = "TCP_TIMEOUT"
        result["error"] = str(exc)
        return None
    except OSError as exc:
        result["tcp_status"] = "FAIL"
        result["tcp_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["status"] = "TCP_FAIL"
        result["error"] = str(exc)
        return None


def parse_cert_time(value):
    """Parse certificate times returned by ssl.getpeercert().

    Used to calculate certificate age, days remaining, and expiry status.
    """
    if not value:
        return None
    return datetime.strptime(value, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)


def format_cert_name(name_tuple):
    """Turn certificate subject/issuer tuple data into readable text.

    Used in CSV and JSON output for easier diagnostic review.
    """
    if not name_tuple:
        return ""
    parts = []
    for section in name_tuple:
        for key, value in section:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def set_cert_status(result, not_before, not_after, warning_days):
    """Evaluate certificate validity window and expiry warning status.

    Used after TLS succeeds to decide whether the certificate is OK, expired,
    not yet valid, or expiring soon.
    """
    now = datetime.now(timezone.utc)
    if not_before:
        result["cert_not_before"] = not_before.isoformat(timespec="seconds")
    if not_after:
        result["cert_not_after"] = not_after.isoformat(timespec="seconds")
    if not_before and not_after:
        result["cert_days_since_start"] = max((now - not_before).days, 0)
        result["cert_days_remaining"] = (not_after - now).days
        result["cert_total_days"] = (not_after - not_before).days
    if not_before and now < not_before:
        result["cert_valid"] = False
        result["cert_status"] = "NOT_YET_VALID"
        result["status"] = "CERT_NOT_YET_VALID"
    elif not_after and now > not_after:
        result["cert_valid"] = False
        result["cert_status"] = "EXPIRED"
        result["status"] = "CERT_EXPIRED"
    else:
        result["cert_valid"] = True
        days_remaining = result.get("cert_days_remaining")
        if isinstance(days_remaining, int) and days_remaining <= warning_days:
            result["cert_status"] = "EXPIRING_SOON"
            result["status"] = "CERT_EXPIRING_SOON"
        else:
            result["cert_status"] = "OK"
            result["status"] = "OK"


def tls_and_cert_check(host, port, timeout, warning_days, result):
    """Perform TLS handshake and certificate validation.

    Used for TCP/443 services because an HTTPS endpoint must be reachable, able
    to negotiate TLS, and present a valid certificate for R1 readiness.
    """
    start = time.perf_counter()
    raw_sock = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            result["tls_status"] = "OK"
            result["tls_ms"] = rounded((time.perf_counter() - start) * 1000)
            cert = tls_sock.getpeercert()
            result["cert_subject"] = format_cert_name(cert.get("subject"))
            result["cert_issuer"] = format_cert_name(cert.get("issuer"))
            set_cert_status(result, parse_cert_time(cert.get("notBefore")), parse_cert_time(cert.get("notAfter")), warning_days)
    except ssl.SSLCertVerificationError as exc:
        result["tls_status"] = "CERT_VERIFY_FAIL"
        result["tls_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["cert_valid"] = False
        result["cert_status"] = "VERIFY_FAIL"
        result["status"] = "CERT_INVALID"
        result["error"] = str(exc)
    except ssl.SSLError as exc:
        result["tls_status"] = "TLS_FAIL"
        result["tls_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["cert_valid"] = False
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    except socket.timeout as exc:
        result["tls_status"] = "TIMEOUT"
        result["tls_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    except OSError as exc:
        result["tls_status"] = "TLS_SOCKET_FAIL"
        result["tls_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    finally:
        try:
            if raw_sock:
                raw_sock.close()
        except OSError:
            pass
    return result


def calculate_response_time(result, udp_strict=False):
    """Set response_ms and response_basis for a completed check.

    Used to produce comparable timing fields for graphing and zone performance
    summaries. The basis explains what was included in the response time.
    """
    dns = safe_float(result.get("dns_ms"))
    tcp = safe_float(result.get("tcp_ms"))
    tls = safe_float(result.get("tls_ms"))
    udp = safe_float(result.get("udp_ms"))
    protocol = result.get("protocol")
    port = int(result.get("port", 0))

    if protocol == "TCP" and port == 443:
        parts, basis = [dns, tcp, tls], "DNS+TCP+TLS"
    elif protocol == "TCP":
        parts, basis = [dns, tcp], "DNS+TCP"
    elif protocol == "UDP" and udp_strict:
        parts, basis = [dns, udp], "DNS+UDP"
    elif protocol == "UDP":
        parts, basis = [dns], "DNS_ONLY"
    else:
        parts, basis = [], "UNSUPPORTED"

    valid_parts = [p for p in parts if p is not None]
    result["response_ms"] = rounded(sum(valid_parts)) if valid_parts else ""
    result["response_basis"] = basis
    return result


def evaluate_service_pass(result, udp_strict=False):
    """Convert raw check outcomes into a service readiness pass/fail value.

    Used by all protocol checks to apply consistent readiness rules before zone
    summaries are calculated.
    """
    calculate_response_time(result, udp_strict=udp_strict)
    protocol = result.get("protocol")
    port = int(result.get("port", 0))

    if result.get("dns_status") != "OK":
        result["service_pass"] = False
        result["service_pass_reason"] = "DNS failed"
        return result

    if protocol == "TCP" and port == 443:
        result["service_pass"] = result.get("tcp_status") == "OPEN" and result.get("tls_status") == "OK" and result.get("cert_valid") is True
        result["service_pass_reason"] = "DNS, TCP, TLS and certificate valid" if result["service_pass"] else "443 requires DNS OK, TCP OPEN, TLS OK and valid certificate"
        if result["service_pass"] and result.get("status") == "CERT_EXPIRING_SOON":
            result["service_pass_reason"] = "PASS with certificate expiry warning"
        return result

    if protocol == "TCP":
        result["service_pass"] = result.get("tcp_status") == "OPEN"
        result["service_pass_reason"] = "DNS OK and TCP OPEN" if result["service_pass"] else "TCP not open"
        return result

    if protocol == "UDP":
        if udp_strict:
            result["service_pass"] = result.get("udp_status") == "RESPONSE"
            result["service_pass_reason"] = "UDP response received" if result["service_pass"] else "UDP did not respond"
        else:
            result["service_pass"] = True
            result["service_pass_reason"] = "DNS OK; UDP response not required in default mode"
        return result

    result["service_pass"] = False
    result["service_pass_reason"] = "Unsupported protocol"
    return result


def check_tcp_target(target, timeout, tls_all, warning_days, udp_strict):
    """Run DNS, TCP, and optional TLS/certificate checks for a TCP target.

    Used by the thread pool for all TCP entries in the hosts file.
    """
    result = empty_result(target["host"], target["port"], "TCP", target.get("zone", "GLOBAL"), target.get("description", ""))
    if not resolve_dns(target["host"], result):
        return evaluate_service_pass(result, udp_strict)
    sock = tcp_connect(target["host"], int(target["port"]), timeout, result)
    if sock is None:
        return evaluate_service_pass(result, udp_strict)
    try:
        sock.close()
    except OSError:
        pass
    if int(target["port"]) == 443 or tls_all:
        result = tls_and_cert_check(target["host"], int(target["port"]), timeout, warning_days, result)
    else:
        result["status"] = "OK"
    return evaluate_service_pass(result, udp_strict)


def check_udp_target(target, timeout, udp_strict):
    """Run DNS and a basic UDP probe for a UDP target.

    Used for RADIUS-style UDP services. Default readiness is DNS-based to avoid
    false failures from generic UDP probes; --udp-strict requires a response.
    """
    result = empty_result(target["host"], target["port"], "UDP", target.get("zone", "GLOBAL"), target.get("description", ""))
    if not resolve_dns(target["host"], result):
        return evaluate_service_pass(result, udp_strict)

    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"port-check", (target["host"], int(target["port"])))
        try:
            sock.recvfrom(1024)
            result["udp_status"] = "RESPONSE"
            result["udp_ms"] = rounded((time.perf_counter() - start) * 1000)
            result["status"] = "OK"
        except socket.timeout:
            result["udp_status"] = "NO_RESPONSE"
            result["udp_ms"] = rounded((time.perf_counter() - start) * 1000)
            result["status"] = "UDP_NO_RESPONSE"
            result["error"] = "No UDP response. This can be normal for UDP services that ignore generic probes."
    except ConnectionRefusedError as exc:
        result["udp_status"] = "UNREACHABLE"
        result["udp_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["status"] = "UDP_UNREACHABLE"
        result["error"] = str(exc)
    except OSError as exc:
        result["udp_status"] = "FAIL"
        result["udp_ms"] = rounded((time.perf_counter() - start) * 1000)
        result["status"] = "UDP_UNREACHABLE"
        result["error"] = str(exc)
    finally:
        sock.close()
    return evaluate_service_pass(result, udp_strict)


def check_target(target, timeout, tls_all, warning_days, udp_strict):
    """Dispatch a target to the correct protocol checker.

    Used by each worker thread to keep protocol-specific checking isolated and
    simple to extend later.
    """
    protocol = target.get("protocol", "TCP").upper()
    if protocol == "TCP":
        return check_tcp_target(target, timeout, tls_all, warning_days, udp_strict)
    if protocol == "UDP":
        return check_udp_target(target, timeout, udp_strict)
    result = empty_result(target.get("host", ""), target.get("port", 0), protocol, target.get("zone", "GLOBAL"), target.get("description", ""))
    result["status"] = "UNSUPPORTED_PROTOCOL"
    result["error"] = f"Unsupported protocol: {protocol}"
    return evaluate_service_pass(result, udp_strict)


def sort_results(results):
    """Sort output by zone, failure priority, host, port, and protocol.

    Used to make console and CSV output easier to scan during troubleshooting.
    """
    zone_order = {"GLOBAL": 0, "US": 1, "EU": 2, "APAC": 3}
    return sorted(results, key=lambda r: (zone_order.get(r.get("zone", "GLOBAL"), 9), STATUS_PRIORITY.get(r.get("status", "UNKNOWN"), 500), str(r.get("host", "")).lower(), int(r.get("port", 0)), str(r.get("protocol", ""))))


def summarize_status(results):
    """Count result rows by status.

    Used in console and JSON metadata for a quick health overview.
    """
    summary = {}
    for result in results:
        status = result.get("status", "UNKNOWN")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items(), key=lambda item: (STATUS_PRIORITY.get(item[0], 500), item[0])))


def response_values(results, passed_only=True):
    """Extract numeric response_ms values for statistics.

    Used by average and median calculations. Passing-only mode avoids failed
    services skewing normal readiness performance metrics.
    """
    values = []
    for r in results:
        if passed_only and r.get("service_pass") is not True:
            continue
        value = safe_float(r.get("response_ms"))
        if value is not None:
            values.append(value)
    return values


def metric_summary(results):
    """Return avg, median, min, max, and sample count for a result set.

    Used for regional and effective timing metrics shown in the readiness table,
    JSON, and history output.
    """
    passing = response_values(results, passed_only=True)
    all_values = response_values(results, passed_only=False)

    def summary(values):
        if not values:
            return {"avg_ms": "", "median_ms": "", "min_ms": "", "max_ms": "", "sample_count": 0}
        return {"avg_ms": rounded(mean(values)), "median_ms": rounded(median(values)), "min_ms": rounded(min(values)), "max_ms": rounded(max(values)), "sample_count": len(values)}

    return {"passing_only": summary(passing), "all_services": summary(all_values)}


def zone_stats(results, zone):
    """Build pass/fail and performance stats for services in a single zone.

    Used by build_readiness to calculate both standalone regional metrics and
    effective GLOBAL+region metrics.
    """
    zone = normalize_zone(zone)
    items = [r for r in results if r.get("zone") == zone]
    passed = sum(1 for r in items if r.get("service_pass") is True)
    metrics = metric_summary(items)
    return {
        "zone": zone,
        "status": "PASS" if items and passed == len(items) else "FAIL",
        "passed": passed,
        "total": len(items),
        "failed": len(items) - passed,
        "failures": [r for r in items if r.get("service_pass") is not True],
        "regional_avg_ms": metrics["passing_only"]["avg_ms"],
        "regional_median_ms": metrics["passing_only"]["median_ms"],
        "regional_min_ms": metrics["passing_only"]["min_ms"],
        "regional_max_ms": metrics["passing_only"]["max_ms"],
        "regional_sample_count": metrics["passing_only"]["sample_count"],
        "regional_avg_ms_all": metrics["all_services"]["avg_ms"],
        "regional_median_ms_all": metrics["all_services"]["median_ms"],
    }


def build_recommendation(readiness):
    """Choose passing zones and fastest passing zone by effective median.

    Used for the console recommendation line, JSON recommendation data, and the
    history file fastest-zone marker.
    """
    passing = []
    for zone in R1_ZONES:
        data = readiness.get(zone, {})
        if data.get("status") == "PASS" and safe_float(data.get("effective_median_ms")) is not None:
            passing.append((zone, float(data["effective_median_ms"])))
    if not passing:
        return {"passing_zones": [], "fastest_passing_zone": "", "fastest_passing_zone_effective_median_ms": ""}
    passing.sort(key=lambda item: (item[1], item[0]))
    return {"passing_zones": [z for z, _ in passing], "fastest_passing_zone": passing[0][0], "fastest_passing_zone_effective_median_ms": rounded(passing[0][1])}


def build_readiness(results):
    """Build GLOBAL and per-region R1 readiness summaries.

    Used after all checks are complete. Each R1 region requires all GLOBAL
    services plus that region's services to pass.
    """
    global_stats = zone_stats(results, "GLOBAL")
    readiness = {"GLOBAL": global_stats}
    global_items = [r for r in results if r.get("zone") == "GLOBAL"]

    for zone in R1_ZONES:
        local = zone_stats(results, zone)
        local_items = [r for r in results if r.get("zone") == zone]
        effective_items = global_items + local_items
        effective_metrics = metric_summary(effective_items)
        total = global_stats["total"] + local["total"]
        passed = global_stats["passed"] + local["passed"]
        readiness[zone] = {
            "zone": zone,
            "global_status": global_stats["status"],
            "regional_status": local["status"],
            "status": "PASS" if global_stats["status"] == "PASS" and local["status"] == "PASS" else "FAIL",
            "global_passed": global_stats["passed"],
            "global_total": global_stats["total"],
            "regional_passed": local["passed"],
            "regional_total": local["total"],
            "passed": passed,
            "total": total,
            "failed": total - passed,
            "failures": list(global_stats["failures"]) + list(local["failures"]),
            "regional_avg_ms": local["regional_avg_ms"],
            "regional_median_ms": local["regional_median_ms"],
            "regional_avg_ms_all": local["regional_avg_ms_all"],
            "regional_median_ms_all": local["regional_median_ms_all"],
            "effective_avg_ms": effective_metrics["passing_only"]["avg_ms"],
            "effective_median_ms": effective_metrics["passing_only"]["median_ms"],
            "effective_min_ms": effective_metrics["passing_only"]["min_ms"],
            "effective_max_ms": effective_metrics["passing_only"]["max_ms"],
            "effective_sample_count": effective_metrics["passing_only"]["sample_count"],
            "effective_avg_ms_all": effective_metrics["all_services"]["avg_ms"],
            "effective_median_ms_all": effective_metrics["all_services"]["median_ms"],
        }
    readiness["recommendation"] = build_recommendation(readiness)
    return readiness


def compact_failures(failures, limit=3):
    """Return a compact failure summary for the readiness table.

    Used to keep console output readable while still exposing the first few
    failing services.
    """
    if not failures:
        return "-"
    items = [f"{r.get('host')}:{r.get('port')} {r.get('status')}" for r in failures[:limit]]
    if len(failures) > limit:
        items.append(f"+{len(failures) - limit} more")
    return "; ".join(items)


def display_value(value):
    """Return a console-safe display value.

    Used by table printers to show '-' for missing values.
    """
    return str(value) if value not in (None, "") else "-"


def print_readiness_table(readiness):
    """Print the high-level R1 readiness and performance table.

    Used before detailed results so the most important outcome is visible first.
    """
    print()
    print("RUCKUS ONE READINESS")
    print("=" * 132)
    header = f"{'ZONE':<8} {'GLOBAL':<10} {'REGIONAL':<10} {'OVERALL':<10} {'PASS/TOTAL':<11} {'REG MED':>9} {'REG AVG':>9} {'EFF MED':>9} {'EFF AVG':>9} {'FAILURES'}"
    print(header)
    print("-" * len(header))

    g = readiness["GLOBAL"]
    print(f"{'GLOBAL':<8} {'-':<10} {'-':<10} {g['status']:<10} {str(g['passed']) + '/' + str(g['total']):<11} {display_value(g.get('regional_median_ms')):>9} {display_value(g.get('regional_avg_ms')):>9} {'-':>9} {'-':>9} {compact_failures(g['failures'])}")
    for zone in R1_ZONES:
        r = readiness[zone]
        print(f"{zone:<8} {r['global_status']:<10} {r['regional_status']:<10} {r['status']:<10} {str(r['passed']) + '/' + str(r['total']):<11} {display_value(r.get('regional_median_ms')):>9} {display_value(r.get('regional_avg_ms')):>9} {display_value(r.get('effective_median_ms')):>9} {display_value(r.get('effective_avg_ms')):>9} {compact_failures(r['failures'])}")

    rec = readiness.get("recommendation", {})
    print("-" * len(header))
    if rec.get("passing_zones"):
        print("Recommended available R1 zones: " + ", ".join(rec["passing_zones"]))
        print(f"Fastest passing R1 zone: {rec['fastest_passing_zone']} ({rec['fastest_passing_zone_effective_median_ms']} ms effective median)")
    else:
        print("Recommended available R1 zones: none, because no region has both GLOBAL and regional services passing")


def print_results(results):
    """Print detailed per-service check results.

    Used for engineering troubleshooting after the high-level readiness table.
    """
    print()
    print("DETAILED CHECK RESULTS")
    print("=" * 132)
    header = f"{'ZONE':<7} {'PASS':<5} {'STATUS':<22} {'HOST':<42} {'PORT':<5} {'PROTO':<5} {'RESP':>8} {'BASIS':<12} {'DNS':<6} {'TCP':<8} {'TLS':<16} {'CERT':<14} {'DAYS':<6} {'IP':<15}"
    print(header)
    print("-" * len(header))
    for r in results:
        days = r.get("cert_days_remaining", "") or "-"
        passed = "YES" if r.get("service_pass") is True else "NO"
        print(f"{r.get('zone',''):<7} {passed:<5} {str(r.get('status','')):<22} {str(r.get('host','')):<42} {str(r.get('port','')):<5} {str(r.get('protocol','')):<5} {display_value(r.get('response_ms')):>8} {str(r.get('response_basis','')):<12} {str(r.get('dns_status','-')):<6} {str(r.get('tcp_status','-')):<8} {str(r.get('tls_status','-')):<16} {str(r.get('cert_status','-')):<14} {str(days):<6} {str(r.get('dns_ip','')):<15}")
    print()
    print("Status summary:")
    for status, count in summarize_status(results).items():
        print(f"  {status:<22} {count}")


def write_csv(path, results):
    """Write detailed check results to CSV.

    Used for per-run analysis in Excel, Power BI, or other tools.
    """
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)


def json_ready_readiness(readiness):
    """Convert readiness data into a compact JSON-safe structure.

    Used so JSON output includes useful failure details without duplicating huge
    nested result objects inside each readiness zone.
    """
    clean = {}
    for zone, data in readiness.items():
        if zone == "recommendation":
            clean[zone] = data
            continue
        clean[zone] = {k: v for k, v in data.items() if k != "failures"}
        clean[zone]["failures"] = [
            {"zone": r.get("zone"), "host": r.get("host"), "port": r.get("port"), "protocol": r.get("protocol"), "status": r.get("status"), "response_ms": r.get("response_ms"), "response_basis": r.get("response_basis"), "service_pass_reason": r.get("service_pass_reason"), "error": r.get("error")}
            for r in data.get("failures", [])
        ]
    return clean


def build_json_payload(results, readiness, args, started_at, finished_at):
    """Build the full JSON result payload.

    Used for the primary JSON output and timestamped archive output.
    """
    return {
        "metadata": {
            "my_org": args.org or "",
            "tool": "port_checker_r1.py",
            "version": VERSION,
            "started_at_utc": started_at,
            "finished_at_utc": finished_at,
            "input_file": str(args.file),
            "result_count": len(results),
            "timeout_seconds": args.timeout,
            "workers": args.workers,
            "tls_all": args.tls_all,
            "udp_strict": args.udp_strict,
            "cert_warning_days": args.cert_warning_days,
            "history_file": args.history_file or "",
            "config_file": args.config,
            "status_summary": summarize_status(results),
            "source": get_source_info(args.skip_public_ip),
        },
        "readiness": json_ready_readiness(readiness),
        "results": results,
    }


def write_json(path, payload):
    """Write JSON data to disk.

    Used for the main JSON output and archive copies.
    """
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def archive_json(payload, archive_dir="json_archive"):
    """Create a timestamped JSON archive file.

    Used to keep per-run JSON snapshots without overwriting the latest output.
    """
    archive_path = Path(archive_dir)
    archive_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_file = archive_path / f"r1_readiness_{timestamp}.json"
    write_json(archive_file, payload)
    return archive_file


def history_rows(readiness, run_timestamp, args):
    """Build one compact history row per zone for long-term graphing.

    Used by append_history_file. The history file stores summary rows rather
    than every service check, keeping the long-term dataset simple and small.
    """
    rec = readiness.get("recommendation", {})
    fastest = rec.get("fastest_passing_zone", "")
    rows = []
    for zone in READINESS_ZONES:
        data = readiness.get(zone, {})
        rows.append({
            "run_timestamp_utc": run_timestamp,
            "tool_version": VERSION,
            "input_file": str(args.file),
            "zone": zone,
            "status": data.get("status", ""),
            "global_status": data.get("global_status", "") if zone != "GLOBAL" else "",
            "regional_status": data.get("regional_status", "") if zone != "GLOBAL" else "",
            "passed": data.get("passed", ""),
            "total": data.get("total", ""),
            "failed": data.get("failed", ""),
            "regional_median_ms": data.get("regional_median_ms", ""),
            "regional_avg_ms": data.get("regional_avg_ms", ""),
            "effective_median_ms": data.get("effective_median_ms", "") if zone != "GLOBAL" else "",
            "effective_avg_ms": data.get("effective_avg_ms", "") if zone != "GLOBAL" else "",
            "fastest_passing_zone": fastest,
            "is_fastest_passing_zone": "YES" if zone == fastest else "NO",
        })
    return rows


def append_history_file(path, readiness, run_timestamp, args):
    """Append compact readiness summary rows to a history CSV file.

    Used when --history-file is supplied. The file is append-only and gets a
    header automatically when it is first created, making it suitable for Excel,
    Power BI, pandas, or simple long-term graphing.
    """
    path = Path(path)
    write_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HISTORY_FIELDS, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerows(history_rows(readiness, run_timestamp, args))
    return path


def load_config_file(path):
    """Load standing default option values from a JSON config file.

    Used by parse_args so a site/org can set defaults (like my_org) without
    repeating CLI switches every run. Holds no passwords/secrets, only the same
    plain settings exposed as CLI switches. A missing file yields no overrides;
    an unreadable or malformed file is skipped with a warning rather than
    failing the run. Unknown keys are ignored.
    """
    path = Path(path)
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"WARNING: Could not read config file {path}: {exc}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        print(f"WARNING: Config file {path} must contain a JSON object, ignoring", file=sys.stderr)
        return {}
    return {key: value for key, value in data.items() if key in CONFIG_DEFAULTS}


def parse_args():
    """Parse command-line arguments.

    Used by main to configure input files, output files, timeouts, threading, TLS
    behaviour, UDP strictness, archiving, and optional history logging. Defaults
    come from (lowest to highest precedence) built-in constants, the JSON config
    file, then explicit CLI switches.
    """
    config_pre_parser = argparse.ArgumentParser(add_help=False)
    config_pre_parser.add_argument("--config", default=DEFAULT_CONFIG_FILE)
    config_args, _ = config_pre_parser.parse_known_args()
    config = dict(CONFIG_DEFAULTS)
    config.update(load_config_file(config_args.config))

    parser = argparse.ArgumentParser(description=f"Ruckus One multi-zone readiness and response checker (v{VERSION}).")
    parser.add_argument("--config", default=config_args.config, help=f"JSON config file providing default option values (default: {DEFAULT_CONFIG_FILE}); CLI switches always override it")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--org", default=config["org"], help="Organization name tag (my_org) recorded in JSON metadata for filtering multi-org results")
    parser.add_argument("-f", "--file", default=config["file"], help=f"Input hosts CSV/text file (default: {DEFAULT_FILE})")
    parser.add_argument("-o", "--output-csv", default=config["output_csv"], help="Output CSV file")
    parser.add_argument("-j", "--output-json", default=config["output_json"], help="Output JSON file")
    parser.add_argument("--history-file", default=config["history_file"], help="Append compact per-run zone summaries to this CSV file for long-term graphing")
    parser.add_argument("--timeout", type=float, default=config["timeout"], help="Socket timeout in seconds")
    parser.add_argument("--workers", type=int, default=config["workers"], help=f"Concurrent worker threads (default: {DEFAULT_WORKERS}, i.e. serial -- raise this for faster, burstier checks)")
    parser.add_argument("--tls-all", action="store_true", default=config["tls_all"], help="Attempt TLS/cert checks for all TCP ports, not only 443")
    parser.add_argument("--udp-strict", action="store_true", default=config["udp_strict"], help="Require UDP response for UDP services to pass readiness")
    parser.add_argument("--cert-warning-days", type=int, default=config["cert_warning_days"], help="Warn when certificate has this many days or fewer remaining")
    parser.add_argument("--no-archive", action="store_true", default=config["no_archive"], help="Do not create timestamped JSON archive copy")
    parser.add_argument("--skip-public-ip", action="store_true", default=config["skip_public_ip"], help="Skip external lookup of the outside NAT IP (hostname/local IP are still recorded)")
    parser.add_argument("--targets-url", default=config["targets_url"], help="Fetch the target list from this URL instead of relying solely on --file; the result is cached to --file, so --file becomes the cache path when this is set")
    parser.add_argument("--targets-cache-hours", type=float, default=config["targets_cache_hours"], help=f"Reuse the cached target list for this many hours before re-fetching (default: {DEFAULT_TARGETS_CACHE_HOURS})")
    return parser.parse_args()


def main():
    """Run the complete Ruckus One readiness workflow.

    Loads targets, runs checks concurrently, calculates zone readiness and timing
    summaries, prints output, writes CSV/JSON, archives JSON, and optionally
    appends long-term history rows.
    """
    args = parse_args()
    started_at = utc_now_iso()
    input_path = Path(args.file)

    if not resolve_targets_file(input_path, args.targets_url, args.targets_cache_hours):
        return 1

    if not input_path.exists():
        print(f"ERROR: Input file not found: {args.file}", file=sys.stderr)
        return 1

    targets = parse_hosts_file(input_path)
    if not targets:
        print("No valid targets found in input file.", file=sys.stderr)
        return 2

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {executor.submit(check_target, t, args.timeout, args.tls_all, args.cert_warning_days, args.udp_strict): t for t in targets}
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                result = empty_result(target.get("host", ""), target.get("port", 0), target.get("protocol", ""), target.get("zone", "GLOBAL"), target.get("description", ""))
                result["status"] = "CHECK_ERROR"
                result["error"] = str(exc)
                results.append(evaluate_service_pass(result, args.udp_strict))

    results = sort_results(results)
    readiness = build_readiness(results)
    finished_at = utc_now_iso()
    payload = build_json_payload(results, readiness, args, started_at, finished_at)

    print_readiness_table(readiness)
    print_results(results)

    write_csv(args.output_csv, results)
    write_json(args.output_json, payload)
    print(f"CSV written:     {args.output_csv}")
    print(f"JSON written:    {args.output_json}")

    if args.history_file:
        history_path = append_history_file(args.history_file, readiness, finished_at, args)
        print(f"History appended:{history_path}")

    if not args.no_archive:
        archive_file = archive_json(payload)
        print(f"JSON archive:    {archive_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
