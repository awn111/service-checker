#!/usr/bin/env python3
"""
port_checker_r1.py
Version: 1.2.1

Ruckus One readiness and regional response checker using Python built-in libraries only.

This version adds function-level docstrings so the script is easier to maintain,
review, hand over, and extend during field testing.

What it checks
--------------
- DNS resolution for all entries
- TCP connect for TCP services
- UDP basic probe for UDP services
- TLS handshake and certificate validity for TCP/443 services
- Region readiness for Ruckus One zones: GLOBAL, US, EU, APAC
- Per-service response_ms and response_basis
- Regional and effective R1 response average and median

Host file format
----------------
Default input file is hosts_r1.csv in the current directory.
Use markdown-style headings to group services:

    # GLOBAL
    ap-registrar.ruckuswireless.com,443
    sw-registrar.ruckuswireless.com,443
    storage.googleapis.com,443

    # US
    ruckus.cloud,443
    device.ruckus.cloud,443
    edge-docker-registry.ruckus.cloud,443

    # EU
    eu.ruckus.cloud,443
    device.eu.ruckus.cloud,443

    # APAC
    asia.ruckus.cloud,443
    device.asia.ruckus.cloud,443

Input formats supported
-----------------------
    host,port
    host,port,protocol
    host,port,protocol,description
    https://ruckus.cloud
    device.ruckus.cloud:443

Readiness logic
---------------
- TCP/443 passes when DNS OK, TCP OPEN, TLS OK and certificate is valid.
- TCP/80 and TCP/22 pass when DNS OK and TCP OPEN.
- UDP services default to DNS-only pass logic, because many UDP services ignore generic probes.
  Use --udp-strict to require a UDP response.

Response timing logic
---------------------
- TCP/443 response_ms = DNS + TCP + TLS
- Other TCP response_ms = DNS + TCP
- UDP default response_ms = DNS only
- UDP strict response_ms = DNS + UDP

Example usage
-------------
    python3 port_checker_r1.py
    python3 port_checker_r1.py -f hosts_r1.csv
    python3 port_checker_r1.py -f customer_hosts.csv -o results.csv -j results.json
    python3 port_checker_r1.py --workers 30 --timeout 5
    python3 port_checker_r1.py --udp-strict

Future CLI note
---------------
The -i short option is intentionally unused and reserved for future interface selection.
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

VERSION = "1.2.1"
DEFAULT_FILE = "hosts_r1.csv"
DEFAULT_TIMEOUT = 5.0
DEFAULT_WORKERS = 20
DEFAULT_CERT_WARNING_DAYS = 30
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"
UDP_DEFAULT_PORTS = {1812, 1813}
KNOWN_ZONES = {"GLOBAL", "US", "EU", "APAC", "ASIA"}
READINESS_ZONES = ["GLOBAL", "US", "EU", "APAC"]

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
    "UNSUPPORTED_PROTOCOL": 900,
    "OK": 999,
}


def utc_now_iso():
    """Return the current UTC time as an ISO formatted string.

    Used whenever the script needs a stable timestamp for result rows, JSON
    metadata, and archive file naming. Keeping this in one function ensures all
    output timestamps use the same timezone and format.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_zone(value):
    """Normalize a zone label into one of GLOBAL, US, EU, or APAC.

    Used by the parser and reporting logic so headings such as '# ASIA' map to
    the APAC readiness bucket. This keeps the host file flexible while ensuring
    the readiness table has consistent zone names.
    """
    value = (value or "GLOBAL").strip().upper()
    if value == "ASIA":
        return "APAC"
    if value in READINESS_ZONES:
        return value
    return "GLOBAL"


def parse_zone_heading(line):
    """Detect whether a line is a markdown-style zone heading.

    Used while reading the hosts file. If a line such as '# GLOBAL' or '## EU'
    is found, the parser updates the current zone for subsequent host entries.
    This allows the host file to stay readable and easy to maintain.
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
    """Convert a value to float, returning None when conversion is not possible.

    Used by timing and statistics functions because result fields may contain
    either numeric timing values or blanks. This keeps summary calculations from
    failing when a check did not reach a measurable stage.
    """
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def rounded(value, digits=2):
    """Round numeric values for console, CSV, and JSON output.

    Used to keep timing values readable without losing useful precision. Returns
    a blank string for missing values so output files remain clean.
    """
    if value is None:
        return ""
    return round(float(value), digits)


def empty_result(host, port, protocol, zone="GLOBAL", description=""):
    """Create a complete result dictionary with default values.

    Used at the start of every service check and when an unexpected exception is
    caught. Having one template ensures CSV/JSON output always has consistent
    columns, even when DNS, TCP, TLS, or UDP checks fail early.
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

    Used when the host file contains URLs instead of explicit host,port rows.
    This allows entries like 'https://ruckus.cloud' to become port 443 and
    'http://ocsp.entrust.net' to become port 80 automatically.
    """
    scheme = (scheme or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def strip_url_to_host_port(value):
    """Extract a hostname and optional port from a URL or host:port string.

    Used by the input parser so the hosts file can accept plain hostnames,
    URLs, or host:port entries. This keeps the tool forgiving when endpoint
    lists are copied from documentation or web pages.
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
    """Determine the protocol to use for a target.

    Used when the host file omits the protocol column. TCP is the default, but
    RADIUS ports 1812 and 1813 default to UDP to match the Ruckus One proxy
    services use case.
    """
    if protocol:
        return protocol.strip().upper()
    if int(port) in UDP_DEFAULT_PORTS:
        return "UDP"
    return "TCP"


def is_header_row(fields):
    """Return True when a parsed CSV row looks like a header row.

    Used by the file parser so optional headings such as 'host,port,protocol'
    are ignored rather than treated as targets. This makes the input file easier
    for humans to read and edit.
    """
    normalized = [f.strip().lower() for f in fields]
    return bool(normalized and normalized[0] in {"host", "hostname", "fqdn", "url"})


def parse_hosts_file(path):
    """Parse the host list into structured target dictionaries.

    Used at program startup to convert the local R1 endpoint file into work
    items for the checker threads. It handles markdown zone headings, comments,
    blank lines, URLs, host:port values, and CSV rows.
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

            protocol = normalize_protocol(protocol, port)
            zone = normalize_zone(explicit_zone or current_zone)
            targets.append({
                "host": host,
                "port": port,
                "protocol": protocol,
                "description": description,
                "zone": zone,
                "source_line": line_number,
            })

    return targets


def resolve_dns(host, result):
    """Resolve a hostname and record DNS timing and addresses.

    Used as the first stage for every service check. DNS success is required for
    all readiness decisions, and the timing contributes to response_ms for all
    protocols.
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
    """Attempt a TCP connection and record connect timing.

    Used for TCP services, including HTTPS, HTTP, and SSH checks. A successful
    connect proves the endpoint is reachable on that port from the local test
    point.
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
    """Parse the date format returned by ssl.getpeercert().

    Used when calculating certificate age, expiry, days remaining, and total
    certificate lifetime. These values are useful for both readiness and
    troubleshooting output.
    """
    if not value:
        return None
    return datetime.strptime(value, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)


def format_cert_name(name_tuple):
    """Convert certificate subject or issuer tuples into readable text.

    Used for CSV and JSON output so certificate details can be inspected without
    needing to understand Python's nested certificate tuple format.
    """
    if not name_tuple:
        return ""
    parts = []
    for section in name_tuple:
        for key, value in section:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def set_cert_status(result, not_before, not_after, warning_days):
    """Evaluate certificate validity and populate certificate status fields.

    Used after a successful TLS handshake. It determines whether the certificate
    is valid, expired, not yet valid, or close to expiry, then records dates and
    day counts for reporting.
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
    """Perform TLS handshake and certificate validation for a TCP endpoint.

    Used automatically for TCP/443 services, and optionally for other TCP ports
    with --tls-all. This is required for Ruckus One HTTPS readiness because TCP
    reachability alone does not prove TLS negotiation or certificate validity.
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
            set_cert_status(
                result,
                parse_cert_time(cert.get("notBefore")),
                parse_cert_time(cert.get("notAfter")),
                warning_days,
            )
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
    """Calculate response_ms and response_basis for a completed result.

    Used after each service check to create a single timing value for summary
    reporting. The basis explains which measurements contributed to response_ms,
    which is essential when comparing TCP, TLS, and UDP checks fairly.
    """
    dns = safe_float(result.get("dns_ms"))
    tcp = safe_float(result.get("tcp_ms"))
    tls = safe_float(result.get("tls_ms"))
    udp = safe_float(result.get("udp_ms"))
    protocol = result.get("protocol")
    port = int(result.get("port", 0))

    if protocol == "TCP" and port == 443:
        parts = [dns, tcp, tls]
        basis = "DNS+TCP+TLS"
    elif protocol == "TCP":
        parts = [dns, tcp]
        basis = "DNS+TCP"
    elif protocol == "UDP" and udp_strict:
        parts = [dns, udp]
        basis = "DNS+UDP"
    elif protocol == "UDP":
        parts = [dns]
        basis = "DNS_ONLY"
    else:
        parts = []
        basis = "UNSUPPORTED"

    valid_parts = [p for p in parts if p is not None]
    if valid_parts:
        result["response_ms"] = rounded(sum(valid_parts))
    else:
        result["response_ms"] = ""
    result["response_basis"] = basis
    return result


def evaluate_service_pass(result, udp_strict=False):
    """Apply service-level pass/fail rules and record the reason.

    Used by all protocol checkers after measurements are captured. It translates
    raw DNS/TCP/TLS/UDP results into the readiness boolean that feeds the zone
    pass/fail table.
    """
    calculate_response_time(result, udp_strict=udp_strict)
    protocol = result.get("protocol")
    port = int(result.get("port", 0))

    if result.get("dns_status") != "OK":
        result["service_pass"] = False
        result["service_pass_reason"] = "DNS failed"
        return result

    if protocol == "TCP" and port == 443:
        if result.get("tcp_status") == "OPEN" and result.get("tls_status") == "OK" and result.get("cert_valid") is True:
            result["service_pass"] = True
            if result.get("status") == "CERT_EXPIRING_SOON":
                result["service_pass_reason"] = "PASS with certificate expiry warning"
            else:
                result["service_pass_reason"] = "DNS, TCP, TLS and certificate valid"
        else:
            result["service_pass"] = False
            result["service_pass_reason"] = "443 requires DNS OK, TCP OPEN, TLS OK and valid certificate"
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
            result["service_pass"] = result.get("dns_status") == "OK"
            result["service_pass_reason"] = "DNS OK; UDP response not required in default mode"
        return result

    result["service_pass"] = False
    result["service_pass_reason"] = "Unsupported protocol"
    return result


def check_tcp_target(target, timeout, tls_all, warning_days, udp_strict):
    """Run the full TCP check path for a target.

    Used for TCP services in each worker thread. It performs DNS, TCP connect,
    and, for HTTPS services, TLS/certificate validation before evaluating
    readiness.
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
    """Run the UDP check path for a target.

    Used for UDP services such as RADIUS 1812/1813. The default readiness mode
    relies on DNS success to avoid false failures from services that ignore
    generic UDP payloads. Strict mode requires an actual UDP response.
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
    """Dispatch a target to the correct protocol-specific checker.

    Used by the thread pool so each parsed host entry is checked according to
    its protocol. This function keeps the main concurrency loop simple and makes
    it easier to add future protocols.
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
    """Sort results for readable console and file output.

    Used after all checks complete. Results are grouped by zone, then by status
    priority, then by host and port so failures appear near the top of each zone.
    """
    zone_order = {"GLOBAL": 0, "US": 1, "EU": 2, "APAC": 3}
    return sorted(results, key=lambda r: (
        zone_order.get(r.get("zone", "GLOBAL"), 9),
        STATUS_PRIORITY.get(r.get("status", "UNKNOWN"), 500),
        str(r.get("host", "")).lower(),
        int(r.get("port", 0)),
        str(r.get("protocol", "")),
    ))


def summarize_status(results):
    """Count results by status value.

    Used for the console status summary and JSON metadata. This gives a quick
    view of overall result health without reading every detailed row.
    """
    summary = {}
    for result in results:
        status = result.get("status", "UNKNOWN")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items(), key=lambda item: (STATUS_PRIORITY.get(item[0], 500), item[0])))


def response_values(results, passed_only=True):
    """Extract numeric response_ms values from result rows.

    Used by average and median calculations. By default it only includes passing
    services so failed timeouts or partial checks do not distort the readiness
    performance metrics.
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
    """Calculate response timing statistics for a set of results.

    Used for regional and effective R1 performance reporting. It returns metrics
    for passing services and all services so the console can stay practical
    while JSON preserves deeper diagnostic data.
    """
    passing = response_values(results, passed_only=True)
    all_values = response_values(results, passed_only=False)

    def summary(values):
        if not values:
            return {"avg_ms": "", "median_ms": "", "min_ms": "", "max_ms": "", "sample_count": 0}
        return {
            "avg_ms": rounded(mean(values)),
            "median_ms": rounded(median(values)),
            "min_ms": rounded(min(values)),
            "max_ms": rounded(max(values)),
            "sample_count": len(values),
        }

    return {
        "passing_only": summary(passing),
        "all_services": summary(all_values),
    }


def zone_stats(results, zone):
    """Build pass/fail and timing statistics for one zone.

    Used by the readiness builder. It summarizes the services that belong only
    to the requested zone, such as GLOBAL-only or EU-only services.
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
    """Select passing zones and the fastest passing R1 zone.

    Used after readiness metrics are built. The fastest zone is selected using
    effective median response time because it is less affected by outliers than
    a simple average.
    """
    passing = []
    for zone in ["US", "EU", "APAC"]:
        data = readiness.get(zone, {})
        if data.get("status") == "PASS" and safe_float(data.get("effective_median_ms")) is not None:
            passing.append((zone, float(data["effective_median_ms"])))
    if not passing:
        return {
            "passing_zones": [],
            "fastest_passing_zone": "",
            "fastest_passing_zone_effective_median_ms": "",
        }
    passing.sort(key=lambda item: (item[1], item[0]))
    return {
        "passing_zones": [z for z, _ in passing],
        "fastest_passing_zone": passing[0][0],
        "fastest_passing_zone_effective_median_ms": rounded(passing[0][1]),
    }


def build_readiness(results):
    """Build the full GLOBAL, US, EU, and APAC readiness model.

    Used after all individual checks have completed. It combines GLOBAL services
    with each regional service group because an R1 zone passes only when both
    global and regional requirements pass.
    """
    global_stats = zone_stats(results, "GLOBAL")
    readiness = {"GLOBAL": global_stats}
    global_items = [r for r in results if r.get("zone") == "GLOBAL"]

    for zone in ["US", "EU", "APAC"]:
        local = zone_stats(results, zone)
        local_items = [r for r in results if r.get("zone") == zone]
        effective_items = global_items + local_items
        effective_metrics = metric_summary(effective_items)
        overall_failures = list(global_stats["failures"]) + list(local["failures"])
        overall_total = global_stats["total"] + local["total"]
        overall_passed = global_stats["passed"] + local["passed"]
        readiness[zone] = {
            "zone": zone,
            "global_status": global_stats["status"],
            "regional_status": local["status"],
            "status": "PASS" if global_stats["status"] == "PASS" and local["status"] == "PASS" else "FAIL",
            "global_passed": global_stats["passed"],
            "global_total": global_stats["total"],
            "regional_passed": local["passed"],
            "regional_total": local["total"],
            "passed": overall_passed,
            "total": overall_total,
            "failed": overall_total - overall_passed,
            "failures": overall_failures,
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
    """Format a short failure list for the readiness table.

    Used to keep the console table compact while still showing which services
    caused a zone to fail. Full failure details remain available in CSV and JSON.
    """
    if not failures:
        return "-"
    items = [f"{r.get('host')}:{r.get('port')} {r.get('status')}" for r in failures[:limit]]
    if len(failures) > limit:
        items.append(f"+{len(failures) - limit} more")
    return "; ".join(items)


def display_value(value):
    """Return a printable value, replacing blanks with a dash.

    Used by console output functions so missing values appear as '-' instead of
    empty strings, improving readability in aligned tables.
    """
    return str(value) if value not in (None, "") else "-"


def print_readiness_table(readiness):
    """Print the high-level Ruckus One readiness table.

    Used before detailed results to show the most important outcome first:
    whether each R1 zone passes, how fast it appears, and which zone is the
    fastest passing candidate based on effective median response time.
    """
    print()
    print("RUCKUS ONE READINESS")
    print("=" * 132)
    header = (
        f"{'ZONE':<8} {'GLOBAL':<10} {'REGIONAL':<10} {'OVERALL':<10} {'PASS/TOTAL':<11} "
        f"{'REG MED':>9} {'REG AVG':>9} {'EFF MED':>9} {'EFF AVG':>9} {'FAILURES'}"
    )
    print(header)
    print("-" * len(header))

    g = readiness["GLOBAL"]
    print(
        f"{'GLOBAL':<8} {'-':<10} {'-':<10} {g['status']:<10} {str(g['passed']) + '/' + str(g['total']):<11} "
        f"{display_value(g.get('regional_median_ms')):>9} {display_value(g.get('regional_avg_ms')):>9} "
        f"{'-':>9} {'-':>9} {compact_failures(g['failures'])}"
    )
    for zone in ["US", "EU", "APAC"]:
        r = readiness[zone]
        pass_total = f"{r['passed']}/{r['total']}"
        print(
            f"{zone:<8} {r['global_status']:<10} {r['regional_status']:<10} {r['status']:<10} {pass_total:<11} "
            f"{display_value(r.get('regional_median_ms')):>9} {display_value(r.get('regional_avg_ms')):>9} "
            f"{display_value(r.get('effective_median_ms')):>9} {display_value(r.get('effective_avg_ms')):>9} "
            f"{compact_failures(r['failures'])}"
        )

    rec = readiness.get("recommendation", {})
    print("-" * len(header))
    if rec.get("passing_zones"):
        print("Recommended available R1 zones: " + ", ".join(rec["passing_zones"]))
        print(
            "Fastest passing R1 zone: "
            f"{rec['fastest_passing_zone']} "
            f"({rec['fastest_passing_zone_effective_median_ms']} ms effective median)"
        )
    else:
        print("Recommended available R1 zones: none, because no region has both GLOBAL and regional services passing")


def print_results(results):
    """Print the detailed per-service result table.

    Used after the readiness table to provide engineering-level troubleshooting
    detail, including response timing basis, DNS/TCP/TLS/cert status, and IP
    resolution for every target.
    """
    print()
    print("DETAILED CHECK RESULTS")
    print("=" * 132)
    header = (
        f"{'ZONE':<7} {'PASS':<5} {'STATUS':<22} {'HOST':<42} {'PORT':<5} "
        f"{'PROTO':<5} {'RESP':>8} {'BASIS':<12} {'DNS':<6} {'TCP':<8} {'TLS':<16} {'CERT':<14} {'DAYS':<6} {'IP':<15}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        days = r.get("cert_days_remaining", "") or "-"
        passed = "YES" if r.get("service_pass") is True else "NO"
        print(
            f"{r.get('zone',''):<7} {passed:<5} {str(r.get('status','')):<22} "
            f"{str(r.get('host','')):<42} {str(r.get('port','')):<5} {str(r.get('protocol','')):<5} "
            f"{display_value(r.get('response_ms')):>8} {str(r.get('response_basis','')):<12} "
            f"{str(r.get('dns_status','-')):<6} {str(r.get('tcp_status','-')):<8} "
            f"{str(r.get('tls_status','-')):<16} {str(r.get('cert_status','-')):<14} "
            f"{str(days):<6} {str(r.get('dns_ip','')):<15}"
        )
    print()
    print("Status summary:")
    for status, count in summarize_status(results).items():
        print(f"  {status:<22} {count}")


def write_csv(path, results):
    """Write detailed result rows to a CSV file.

    Used so results can be opened in Excel or fed into another reporting tool.
    The CSV includes all diagnostic fields, not just the console summary.
    """
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def json_ready_readiness(readiness):
    """Convert readiness data into JSON-safe compact structures.

    Used before writing JSON because raw failure lists contain full result
    dictionaries. This function keeps the JSON readable while preserving the
    key failure details needed for automation or dashboards.
    """
    clean = {}
    for zone, data in readiness.items():
        if zone == "recommendation":
            clean[zone] = data
            continue
        clean[zone] = {k: v for k, v in data.items() if k != "failures"}
        clean[zone]["failures"] = [
            {
                "zone": r.get("zone"),
                "host": r.get("host"),
                "port": r.get("port"),
                "protocol": r.get("protocol"),
                "status": r.get("status"),
                "response_ms": r.get("response_ms"),
                "response_basis": r.get("response_basis"),
                "service_pass_reason": r.get("service_pass_reason"),
                "error": r.get("error"),
            }
            for r in data.get("failures", [])
        ]
    return clean


def build_json_payload(results, readiness, args, started_at, finished_at):
    """Assemble the complete JSON payload for output.

    Used after checks and readiness calculations complete. The payload includes
    metadata, readiness summaries, recommendations, and every detailed result so
    the run can be archived or processed later.
    """
    return {
        "metadata": {
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
            "status_summary": summarize_status(results),
        },
        "readiness": json_ready_readiness(readiness),
        "results": results,
    }


def write_json(path, payload):
    """Write the JSON payload to disk.

    Used for the primary JSON result file and by the archive writer. JSON output
    is useful for automation, historical comparison, and future dashboarding.
    """
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def archive_json(payload, archive_dir="json_archive"):
    """Create a timestamped JSON archive copy of the run.

    Used to preserve historical readiness results without overwriting the latest
    JSON file. This supports later trend analysis and field test comparison.
    """
    archive_path = Path(archive_dir)
    archive_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_file = archive_path / f"r1_readiness_{timestamp}.json"
    write_json(archive_file, payload)
    return archive_file


def parse_args():
    """Parse command-line options for the checker.

    Used by main() to control input file, output files, timeout, threading, TLS
    behaviour, UDP strictness, certificate warning thresholds, and archiving.
    The -i option is intentionally not defined so it can later be used for
    interface selection.
    """
    parser = argparse.ArgumentParser(description="Ruckus One multi-zone readiness and response checker.")
    parser.add_argument("-f", "--file", default=DEFAULT_FILE, help=f"Input hosts CSV/text file (default: {DEFAULT_FILE})")
    parser.add_argument("-o", "--output-csv", default="r1_port_check_results.csv", help="Output CSV file")
    parser.add_argument("-j", "--output-json", default="r1_port_check_results.json", help="Output JSON file")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout in seconds")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent worker threads")
    parser.add_argument("--tls-all", action="store_true", help="Attempt TLS/cert checks for all TCP ports, not only 443")
    parser.add_argument("--udp-strict", action="store_true", help="Require UDP response for UDP services to pass readiness")
    parser.add_argument("--cert-warning-days", type=int, default=DEFAULT_CERT_WARNING_DAYS, help="Warn when certificate has this many days or fewer remaining")
    parser.add_argument("--no-archive", action="store_true", help="Do not create timestamped JSON archive copy")
    return parser.parse_args()


def main():
    """Run the full Ruckus One readiness workflow.

    This is the program entry point. It parses arguments, loads targets, runs
    checks concurrently, builds readiness and timing summaries, prints reports,
    and writes CSV/JSON outputs.
    """
    args = parse_args()
    started_at = utc_now_iso()
    input_path = Path(args.file)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {args.file}", file=sys.stderr)
        return 1

    targets = parse_hosts_file(input_path)
    if not targets:
        print("No valid targets found in input file.", file=sys.stderr)
        return 2

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(check_target, target, args.timeout, args.tls_all, args.cert_warning_days, args.udp_strict): target
            for target in targets
        }
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                result = empty_result(target.get("host", ""), target.get("port", 0), target.get("protocol", ""), target.get("zone", "GLOBAL"), target.get("description", ""))
                result["status"] = "CHECK_ERROR"
                result["error"] = str(exc)
                result = evaluate_service_pass(result, args.udp_strict)
                results.append(result)

    results = sort_results(results)
    readiness = build_readiness(results)
    finished_at = utc_now_iso()
    payload = build_json_payload(results, readiness, args, started_at, finished_at)

    print_readiness_table(readiness)
    print_results(results)

    write_csv(args.output_csv, results)
    write_json(args.output_json, payload)
    print(f"CSV written:  {args.output_csv}")
    print(f"JSON written: {args.output_json}")
    if not args.no_archive:
        archive_file = archive_json(payload)
        print(f"JSON archive: {archive_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
