# SOC TI Checker

`SOC TI Checker` is a console-based threat intelligence enrichment tool for SOC workflows.

The script accepts raw text, logs, alerts, IOC dumps, IP addresses, and URLs directly from the terminal. It automatically extracts public IPv4 addresses and URLs, checks them against multiple threat intelligence sources, and prints a readable summary for quick triage.

## Features

- Extracts public IPv4 addresses from raw text
- Extracts URLs from raw text
- Checks IPs in:
  - VirusTotal
  - AbuseIPDB
  - AlienVault OTX
  - Shodan
- Checks URLs in VirusTotal
- Supports direct terminal workflow without GUI
- Accepts either commands or new text directly in the prompt
- Provides a separate command for listing IPs with `AbuseIPDB score >= 10`
- Hides API keys from printed HTTP error messages

## How It Works

1. Run the script
2. Paste text, logs, IPs, or URLs
3. Press `Enter` on an empty line
4. The script extracts IOC automatically and starts enrichment
5. After the scan, you can enter either:
   - commands such as `stats`, `ips`, `urls`, `bad_abuse`
   - or new text / URL / IP directly in the `soc>` prompt

## Supported Commands

- `check` - re-run checks for the last extracted IOC set
- `bad_abuse` - show IPs with `AbuseIPDB score >= 10`
- `urls` - print the latest URL results
- `ips` - print the latest IP results
- `stats` - show a short summary
- `clear` - clear the current session
- `help` - show available commands
- `exit` - close the program

Any other text entered in the `soc>` prompt is treated as new input for analysis.

## Required API Keys

The script reads API keys from environment variables:

- `VT_API_KEY`
- `ABUSEIPDB_API_KEY`
- `OTX_API_KEY`
- `SHODAN_API_KEY`

PowerShell example:

```powershell
$env:VT_API_KEY="your_virustotal_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
$env:OTX_API_KEY="your_otx_key"
$env:SHODAN_API_KEY="your_shodan_key"
```

## Run

```powershell
python .\IP_checker.py
```

If `python` is not available in your terminal, use the Python launcher or the full path to your interpreter.

## Example Workflow

```text
python .\IP_checker.py

SOC TI Checker
Сразу вставь текст. Когда закончишь, нажми Enter на пустой строке.

Failed login from 8.8.8.8
Suspicious callback to https://example.com/test

```

After that, the tool:

- extracts the IP address
- extracts the URL
- checks them against TI sources
- prints the results directly in the terminal

Then you can continue with:

```text
soc> stats
soc> bad_abuse
soc> ips
soc> https://example.org/login
```

## Typical Use Cases

- IOC triage during incident response
- Fast enrichment of suspicious IPs from logs
- URL reputation checks during phishing analysis
- Quick preparation of blocklists from AbuseIPDB results
- Demonstrating practical SOC automation skills in a portfolio

## File

- [`IP_checker.py`](./IP_checker.py) - main console-based checker
