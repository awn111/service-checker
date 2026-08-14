# Ruckus One Service Checker

Python tools for checking Ruckus One service readiness across the GLOBAL, US,
EU, and APAC zones.

The checker reads a host and port list, performs DNS, TCP, UDP, TLS, and
certificate checks, and reports service and regional readiness. The command
line checker uses only the Python standard library. Optional GUI front ends are
also included.

## Features

- DNS resolution checks for every target
- TCP connection checks
- Optional UDP response checks
- TLS handshake and certificate validity checks for TCP/443
- Regional readiness summaries for GLOBAL, US, EU, and APAC
- Concurrent checks using worker threads
- CSV and JSON result files
- Timestamped JSON archives
- Optional append-only history CSV for reporting and graphing

## Requirements

- Python 3.9 or newer
- Network access to the services being tested

The CLI tools use Python built-in libraries only. The Qt GUI additionally
requires PySide6. The Tkinter GUI requires a Python installation with Tkinter
available.

## Quick Start

Run the current R1 checker with the included host list:

```powershell
python port_checker_r1_v1_2_2.py
```

Use a different input file and keep a long-term readiness history:

```powershell
python port_checker_r1_v1_2_2.py `
  --file customer_hosts.csv `
  --history-file r1_history.csv
```

The default run creates:

- `r1_port_check_results.csv`: one row per checked service
- `r1_port_check_results.json`: detailed results and readiness metadata
- `r1_port_check_results_YYYYMMDD_HHMMSS.json`: timestamped JSON archive

Generated result files are not required inputs for a later run and can be
deleted or redirected with the output options.

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

The recommended script is `port_checker_r1_v1_2_2.py`.

| Option | Description | Default |
| --- | --- | --- |
| `-f`, `--file` | Input hosts CSV/text file | `hosts_r1.csv` |
| `-o`, `--output-csv` | CSV result path | `r1_port_check_results.csv` |
| `-j`, `--output-json` | JSON result path | `r1_port_check_results.json` |
| `--history-file` | Append zone summaries to a history CSV | Disabled |
| `--timeout` | Socket timeout in seconds | `5` |
| `--workers` | Number of concurrent worker threads | `20` |
| `--tls-all` | Attempt TLS and certificate checks on every TCP port | Disabled |
| `--udp-strict` | Require UDP responses for UDP readiness | Disabled |
| `--cert-warning-days` | Certificate warning threshold | `30` |
| `--no-archive` | Disable the timestamped JSON archive | Disabled |

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

## GUI Front Ends

The repository includes two GUI prototypes:

### Qt GUI

Install PySide6 and launch the Qt interface:

```powershell
python -m pip install PySide6
python port_checker_gui.py
```

### Tkinter GUI

Launch the Tkinter interface when Tkinter is available:

```powershell
python port_checker_Tk-gui.py
```

The command-line checker is the recommended path for production checks. The
GUI files are prototypes and may contain demonstration data or incomplete
integration with the current CLI implementation.

## Versioned Scripts

- `port_checker_r1_v1_2_2.py`: latest R1 checker with history logging
- `port_checker_r1_v1_2_1.py`: R1 checker with response timing summaries
- `port_checker_r1_v1_2.py`: earlier R1 checker with regional readiness
- `port_checker_r1.py`: first R1 regional checker
- `port_checker.py`: general-purpose checker without R1 zone summaries

The versioned files are retained for comparison and field-testing history.
Use `port_checker_r1_v1_2_2.py` for new checks unless a previous version is
needed for compatibility.

## Exit Codes

- `0`: check completed successfully
- `1`: input file was not found
- `2`: no valid targets were found in the input file

## License

No license file is currently included in this repository.