# Ruckus One Service Checker

Python tools for checking Ruckus One service readiness across the GLOBAL, US,
EU, and APAC zones.

The checker reads a host and port list, performs DNS, TCP, UDP, TLS, and
certificate checks, and reports service and regional readiness. Uses only
the Python standard library -- nothing to install.

## Features

- DNS resolution checks for every target
- TCP connection checks
- Optional UDP response checks
- TLS handshake and certificate validity checks for TCP/443
- Regional readiness summaries for GLOBAL, US, EU, and APAC
- Configurable concurrency, serial by default (`--workers`)
- CSV and JSON result files
- Timestamped JSON archives
- Optional append-only history CSV for reporting and graphing

## Requirements

- Python 3.9 or newer
- Network access to the services being tested

## Quick Start

Run the current R1 checker with the included host list:

```powershell
python port_checker_r1_v1_2_2.py
```

With the default worker count (serial, one connection at a time) a run
against the included 20-target list takes about 9 seconds; pass a higher
`--workers` for faster, more concurrent checks.

Use a different input file and keep a long-term readiness history:

```powershell
python port_checker_r1_v1_2_2.py `
  --file customer_hosts.csv `
  --history-file r1_history.csv
```

## Config File

Instead of repeating CLI switches every run, copy
`port_checker_r1_config.example.json` to `port_checker_r1_config.json` (default
name, looked up in the current directory) and set standing defaults there,
including `org` (recorded as `my_org` in JSON metadata for filtering
multi-org results). Use `--config path.json` to point at a different file.

Precedence, lowest to highest: built-in defaults -> config file -> explicit CLI
switches. Any CLI switch you pass always overrides the config file. The config
file holds no passwords or secrets, only the same plain settings exposed as
CLI options.

The default run creates:

- `r1_port_check_results.csv`: one row per checked service
- `r1_port_check_results.json`: detailed results and readiness metadata
- `r1_port_check_results_YYYYMMDD_HHMMSS.json`: timestamped JSON archive

Generated result files are not required inputs for a later run and can be
deleted or redirected with the output options.

## Fetching the target list remotely

By default the checker reads targets from a local file (`--file`,
default `hosts_r1.csv`). Set `--targets-url` (or `targets_url` in the
config file) to fetch that file from an ingest service instead, e.g.:

```powershell
python port_checker_r1_v1_2_2.py --targets-url https://your-service.up.railway.app/targets
```

When `--targets-url` is set, `--file` becomes the local cache path: a
fetch writes the response there, and later runs reuse that cache for
`--targets-cache-hours` (default 24) before fetching again. If a fetch
fails -- no network, the service is down -- the checker falls back to
the existing cache with a warning rather than failing the run; it only
fails outright if there is no cache yet to fall back on. This is the
recommended way to point the checker at a centrally-maintained target
list without redistributing this script every time the list changes:
put `targets_url` in your own `port_checker_r1_config.json` (git-ignored,
site-specific) rather than passing it on the command line every time.

## Host File Format

Targets are grouped with headings. Supported zones are `GLOBAL`, `US`, `EU`,
`APAC`, and `ASIA`; `ASIA` is normalized to `APAC`.

```text
# GLOBAL
ap-registrar.ruckuswireless.com,443
storage.googleapis.com,443

# US
ruckus.cloud,443
device.ruckus.cloud,22
outgoing.ruckus.cloud,1812,UDP,RADIUS authentication

# EU
eu.ruckus.cloud,443

# APAC
asia.ruckus.cloud,443
```

Supported row formats are:

```text
host,port
host,port,protocol
host,port,protocol,description
https://example.com
example.com:443
```

If the protocol is omitted, TCP is used by default. Ports `1812` and `1813`
default to UDP. Blank lines, comments, and a header row are ignored.

## Readiness Rules

- TCP/443 passes when DNS, TCP, TLS, and certificate validation pass.
- TCP/80 and TCP/22 pass when DNS and TCP connection checks pass.
- UDP services use DNS-only readiness by default because many UDP services do
  not respond to generic probes.
- `--udp-strict` requires a UDP response for UDP services to pass.
- Certificate warnings use 30 days remaining by default.

## Command-Line Options

| Option | Description | Default |
| --- | --- | --- |
| `-f`, `--file` | Input hosts CSV/text file | `hosts_r1.csv` |
| `-o`, `--output-csv` | CSV result path | `r1_port_check_results.csv` |
| `-j`, `--output-json` | JSON result path | `r1_port_check_results.json` |
| `--history-file` | Append zone summaries to a history CSV | Disabled |
| `--timeout` | Socket timeout in seconds | `5` |
| `--workers` | Number of concurrent worker threads | `1` (serial) |
| `--tls-all` | Attempt TLS and certificate checks on every TCP port | Disabled |
| `--udp-strict` | Require UDP responses for UDP readiness | Disabled |
| `--cert-warning-days` | Certificate warning threshold | `30` |
| `--no-archive` | Disable the timestamped JSON archive | Disabled |
| `--iplookup {yes,no}` | Look up this machine's public IP via a third-party service | Prompts if interactive, else skips |
| `--targets-url` | Fetch the target list from this URL instead of relying solely on `--file` | Disabled |
| `--targets-cache-hours` | Reuse the cached target list this many hours before re-fetching | `24` |

Examples:

```powershell
# Use more workers and a shorter timeout
python port_checker_r1_v1_2_2.py --workers 40 --timeout 3

# Require UDP responses and check TLS on all TCP ports
python port_checker_r1_v1_2_2.py --udp-strict --tls-all

# Write results to a separate directory or filename
python port_checker_r1_v1_2_2.py `
  --output-csv results\services.csv `
  --output-json results\services.json

# Keep only the requested CSV and JSON outputs
python port_checker_r1_v1_2_2.py --no-archive
```

The history CSV is append-only and can be opened with Excel, Power BI, pandas,
or another reporting tool:

```powershell
python port_checker_r1_v1_2_2.py --history-file r1_history.csv
```

## Exit Codes

- `0`: check completed successfully
- `1`: input file was not found
- `2`: no valid targets were found in the input file

## License

No license file is currently included in this repository.