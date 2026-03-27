# SOC TI Checker

SOC TI Checker is a lightweight console-based threat intelligence tool for SOC analysts.

The script allows you to paste logs, alerts, IOC dumps, URLs, or any raw text directly into the terminal. It automatically extracts public IPv4 addresses and URLs using regular expressions, then enriches them with data from multiple threat intelligence sources.

## Features

- Automatic extraction of public IPv4 addresses from raw text
- Automatic extraction of URLs from raw text
- IP reputation checks across:
  - VirusTotal
  - AbuseIPDB
  - AlienVault OTX
  - Shodan
- URL reputation checks via VirusTotal
- Fast console workflow: paste text, get results immediately
- Additional commands for filtering and reviewing results
- Quick list of IPs with `AbuseIPDB score >= 10` for blocklist workflows
- Safe error handling with sanitized API error output

## Workflow

1. Run the script
2. Paste logs, IOC dump, URL, or any text
3. Press Enter on an empty line
4. Get TI enrichment results immediately

After the first check, you can continue working in interactive mode with commands such as:

- `new` — analyze new text
- `check` — re-check the last extracted IOC set
- `bad_abuse` — show IPs with AbuseIPDB score >= 10
- `ips` — show IP results again
- `urls` — show URL results again
- `stats` — show summary
- `clear` — clear current session
- `help` — show help
- `exit` — quit

## Environment Variables

Set your API keys before running the script:

- `VT_API_KEY`
- `ABUSEIPDB_API_KEY`
- `OTX_API_KEY`
- `SHODAN_API_KEY`

## Use Cases

- IOC triage
- SOC alert enrichment
- Quick reputation checks from logs
- Preparing suspicious IPs for blocking
- Fast URL verification from incidents or phishing investigations
