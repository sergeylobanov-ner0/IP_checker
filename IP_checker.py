import base64
import ipaddress
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import requests


# Configuration: API keys, request settings, and scoring threshold.
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

REQUEST_TIMEOUT = 20
USER_AGENT = "SOC-IP-Checker/1.0"
ABUSE_THRESHOLD = 10


# IOC parsing: extract public IPv4 addresses and URLs from arbitrary text.
IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
URL_REGEX = re.compile(r"https?://[^\s\]\[\)\(\"'<>]+", re.IGNORECASE)


def is_public_ipv4(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_global
    except ValueError:
        return False


def extract_public_ips(text: str) -> List[str]:
    unique: List[str] = []
    seen = set()
    for ip in IP_REGEX.findall(text):
        if ip not in seen and is_public_ipv4(ip):
            unique.append(ip)
            seen.add(ip)
    return unique


def extract_urls(text: str) -> List[str]:
    unique: List[str] = []
    seen = set()
    for url in URL_REGEX.findall(text):
        normalized = url.rstrip(".,;")
        if normalized not in seen:
            unique.append(normalized)
            seen.add(normalized)
    return unique


# Result models: keep enrichment data structured and easy to format.
@dataclass
class IPResult:
    ip: str
    abuse_score: Optional[int] = None
    abuse_reports: Optional[int] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    vt_reputation: Optional[int] = None
    otx_pulse_count: Optional[int] = None
    shodan_ports: Optional[List[int]] = None
    shodan_org: Optional[str] = None
    shodan_os: Optional[str] = None
    error: Optional[str] = None


@dataclass
class URLResult:
    url: str
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    error: Optional[str] = None


# Threat intelligence client: one place for all external API requests.
class TIClient:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        if not ABUSEIPDB_API_KEY:
            return {"error": "ABUSEIPDB_API_KEY is not set"}

        try:
            response = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore"),
                "abuse_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
            }
        except Exception as exc:
            return {"error": self._format_service_error("AbuseIPDB", exc)}

    def check_vt_ip(self, ip: str) -> Dict[str, Any]:
        if not VT_API_KEY:
            return {"error": "VT_API_KEY is not set"}

        try:
            response = self.session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_API_KEY},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "vt_malicious": stats.get("malicious"),
                "vt_suspicious": stats.get("suspicious"),
                "vt_harmless": stats.get("harmless"),
                "vt_reputation": data.get("reputation"),
            }
        except Exception as exc:
            return {"error": self._format_service_error("VirusTotal IP", exc)}

    def check_otx_ip(self, ip: str) -> Dict[str, Any]:
        if not OTX_API_KEY:
            return {"error": "OTX_API_KEY is not set"}

        try:
            response = self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return {"otx_pulse_count": len(pulses)}
        except Exception as exc:
            return {"error": self._format_service_error("OTX", exc)}

    def check_shodan_ip(self, ip: str) -> Dict[str, Any]:
        if not SHODAN_API_KEY:
            return {"error": "SHODAN_API_KEY is not set"}

        try:
            response = self.session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": SHODAN_API_KEY},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "shodan_ports": data.get("ports", []),
                "shodan_org": data.get("org"),
                "shodan_os": data.get("os"),
            }
        except Exception as exc:
            return {"error": self._format_service_error("Shodan", exc)}

    def submit_and_check_vt_url(self, target_url: str) -> Dict[str, Any]:
        if not VT_API_KEY:
            return {"error": "VT_API_KEY is not set"}

        headers = {"x-apikey": VT_API_KEY}
        try:
            submit_response = self.session.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": target_url},
                timeout=REQUEST_TIMEOUT,
            )
            submit_response.raise_for_status()

            analysis_id = submit_response.json().get("data", {}).get("id")
            if not analysis_id:
                return {"error": "VirusTotal did not return analysis ID"}

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(8):
                analysis_response = self.session.get(
                    analysis_url,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )
                analysis_response.raise_for_status()
                analysis_data = analysis_response.json().get("data", {}).get("attributes", {})
                if analysis_data.get("status") == "completed":
                    break
                time.sleep(2)

            url_id = self._encode_vt_url_id(target_url)
            url_response = self.session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            url_response.raise_for_status()
            attributes = url_response.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            return {
                "vt_malicious": stats.get("malicious"),
                "vt_suspicious": stats.get("suspicious"),
                "vt_harmless": stats.get("harmless"),
            }
        except Exception as exc:
            return {"error": self._format_service_error("VirusTotal URL", exc)}

    def enrich_ip(self, ip: str) -> IPResult:
        result = IPResult(ip=ip)
        for checker in (
            self.check_abuseipdb,
            self.check_vt_ip,
            self.check_otx_ip,
            self.check_shodan_ip,
        ):
            data = checker(ip)
            for key, value in data.items():
                if key == "error":
                    result.error = f"{result.error} | {value}" if result.error else value
                else:
                    setattr(result, key, value)
        return result

    def enrich_url(self, url: str) -> URLResult:
        result = URLResult(url=url)
        for key, value in self.submit_and_check_vt_url(url).items():
            if key == "error":
                result.error = value
            else:
                setattr(result, key, value)
        return result

    @staticmethod
    def _encode_vt_url_id(target_url: str) -> str:
        encoded = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("ascii")
        return encoded.strip("=")

    @staticmethod
    def _format_service_error(service: str, exc: Exception) -> str:
        message = str(exc)
        if "http://" in message or "https://" in message:
            message = TIClient._sanitize_url_in_error(message)
        return f"{service} error: {message}"

    @staticmethod
    def _sanitize_url_in_error(message: str) -> str:
        sanitized_parts = []
        for part in message.split():
            if part.startswith("http://") or part.startswith("https://"):
                try:
                    parsed = urlsplit(part)
                    sanitized_parts.append(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))
                    continue
                except Exception:
                    pass
            sanitized_parts.append(part)
        return " ".join(sanitized_parts)


# Console workflow: accept text, extract IOC, run checks, and print readable output.
class SOCConsoleApp:
    def __init__(self) -> None:
        self.client = TIClient()
        self.current_text = ""
        self.current_ips: List[str] = []
        self.current_urls: List[str] = []
        self.ip_results: List[IPResult] = []
        self.url_results: List[URLResult] = []

    def run(self) -> None:
        print("SOC TI Checker")
        print("Сразу вставь текст. Когда закончишь, нажми Enter на пустой строке.")
        print("После проверки можно вводить команды или сразу новый текст/URL/IP.")
        self.handle_text(check_after=True)

        while True:
            try:
                raw_input_value = input("\nsoc> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nВыход.")
                return

            if not raw_input_value:
                continue

            command = raw_input_value.lower()
            if command in {"exit", "quit"}:
                print("Выход.")
                return
            if command == "help":
                self.print_help()
            elif command == "check":
                self.run_checks()
            elif command == "bad_abuse":
                self.print_bad_abuse()
            elif command == "urls":
                self.print_urls()
            elif command == "ips":
                self.print_ips()
            elif command == "stats":
                self.print_stats()
            elif command == "clear":
                self.clear()
            else:
                self.handle_text(check_after=True, first_line=raw_input_value)

    def print_help(self) -> None:
        print("check      - повторно проверить IOC из последнего текста")
        print(f"bad_abuse  - вывести IP со score AbuseIPDB >= {ABUSE_THRESHOLD}")
        print("urls       - показать результаты по URL")
        print("ips        - показать результаты по IP")
        print("stats      - краткая сводка")
        print("clear      - очистить текущую сессию")
        print("help       - показать команды")
        print("exit       - выход")
        print("Любой другой ввод в строке soc> считается новым текстом для анализа.")

    def read_multiline_text(self, first_line: Optional[str] = None) -> str:
        if first_line is None:
            print("Вставь текст. Когда закончишь, нажми Enter на пустой строке.")
            lines: List[str] = []
        else:
            print("Распознал ввод как новый текст для анализа. Добавь еще строки или нажми Enter на пустой строке.")
            lines = [first_line]

        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        return "\n".join(lines)

    def handle_text(self, check_after: bool, first_line: Optional[str] = None) -> None:
        self.current_text = self.read_multiline_text(first_line=first_line)
        self.current_ips = extract_public_ips(self.current_text)
        self.current_urls = extract_urls(self.current_text)

        if self.current_ips:
            print(f"Найдено IP: {len(self.current_ips)}")
            for ip in self.current_ips:
                print(f"  {ip}")

        if self.current_urls:
            print(f"Найдено URL: {len(self.current_urls)}")
            for url in self.current_urls:
                print(f"  {url}")

        if check_after:
            self.run_checks()

    def run_checks(self) -> None:
        if not self.current_ips and not self.current_urls:
            print("Нет IOC для проверки. Вставь новый текст.")
            return

        self.ip_results = []
        self.url_results = []

        total = len(self.current_ips) + len(self.current_urls)
        processed = 0

        for ip in self.current_ips:
            processed += 1
            print(f"\n[{processed}/{total}] Проверяю IP: {ip}")
            result = self.client.enrich_ip(ip)
            self.ip_results.append(result)
            self.print_single_ip_result(result)

        for url in self.current_urls:
            processed += 1
            print(f"\n[{processed}/{total}] Проверяю URL: {url}")
            result = self.client.enrich_url(url)
            self.url_results.append(result)
            self.print_single_url_result(result)

        if self.current_ips:
            print("\nПроверка завершена.")
            self.print_stats()
            self.print_bad_abuse()

    def print_stats(self) -> None:
        print(f"Текущих IP: {len(self.current_ips)}")
        print(f"Текущих URL: {len(self.current_urls)}")
        print(f"Проверено IP: {len(self.ip_results)}")
        print(f"Проверено URL: {len(self.url_results)}")
        print(f"Abuse >= {ABUSE_THRESHOLD}: {len(self.get_bad_abuse_ips())}")

    def print_bad_abuse(self) -> None:
        bad_ips = self.get_bad_abuse_ips()
        if not bad_ips:
            print(f"Нет IP со score AbuseIPDB >= {ABUSE_THRESHOLD}.")
            return

        print(f"IP для блокировки (Abuse >= {ABUSE_THRESHOLD}):")
        for ip in bad_ips:
            print(ip)

    def print_urls(self) -> None:
        if not self.url_results:
            print("URL еще не проверялись.")
            return

        for item in self.url_results:
            self.print_single_url_result(item)

    def print_ips(self) -> None:
        if not self.ip_results:
            print("IP еще не проверялись.")
            return

        for item in self.ip_results:
            self.print_single_ip_result(item)

    def clear(self) -> None:
        self.current_text = ""
        self.current_ips = []
        self.current_urls = []
        self.ip_results = []
        self.url_results = []
        print("Сессия очищена.")

    def get_bad_abuse_ips(self) -> List[str]:
        return sorted(item.ip for item in self.ip_results if (item.abuse_score or 0) >= ABUSE_THRESHOLD)

    # Output formatting: compact summary for IP and URL results.
    def print_single_ip_result(self, item: IPResult) -> None:
        abuse_score = item.abuse_score if item.abuse_score is not None else "-"
        abuse_reports = item.abuse_reports if item.abuse_reports is not None else "-"
        vt_mal = item.vt_malicious if item.vt_malicious is not None else "-"
        vt_susp = item.vt_suspicious if item.vt_suspicious is not None else "-"
        vt_rep = item.vt_reputation if item.vt_reputation is not None else "-"
        otx_pulses = item.otx_pulse_count if item.otx_pulse_count is not None else "-"
        ports = ", ".join(str(port) for port in (item.shodan_ports or [])) or "-"

        quick_flags: List[str] = []
        if (item.abuse_score or 0) >= ABUSE_THRESHOLD:
            quick_flags.append(f"ABUSE>={ABUSE_THRESHOLD}")
        if (item.vt_malicious or 0) > 0:
            quick_flags.append("VT_MALICIOUS")
        if (item.otx_pulse_count or 0) > 0:
            quick_flags.append("OTX_HIT")
        if item.shodan_ports:
            quick_flags.append("SHODAN_PORTS")
        verdict = ", ".join(quick_flags) if quick_flags else "no obvious hits"

        print("=" * 78)
        print(f"IP      : {item.ip}")
        print(f"Summary : {verdict}")
        print(f"Abuse   : score={abuse_score} reports={abuse_reports}")
        print(f"VT      : malicious={vt_mal} suspicious={vt_susp} reputation={vt_rep}")
        print(f"OTX     : pulses={otx_pulses}")
        print(f"Shodan  : ports={ports}")
        print(f"Geo/ISP : country={item.country or '-'} | isp={item.isp or '-'}")
        print(f"Usage   : {item.usage_type or '-'}")
        print(f"Org/OS  : org={item.shodan_org or '-'} | os={item.shodan_os or '-'}")
        if item.error:
            print(f"Errors  : {item.error}")

    def print_single_url_result(self, item: URLResult) -> None:
        vt_mal = item.vt_malicious if item.vt_malicious is not None else "-"
        vt_susp = item.vt_suspicious if item.vt_suspicious is not None else "-"
        vt_harm = item.vt_harmless if item.vt_harmless is not None else "-"

        print("=" * 78)
        print(f"URL     : {item.url}")
        print(f"VT      : malicious={vt_mal} suspicious={vt_susp} harmless={vt_harm}")
        if item.error:
            print(f"Errors  : {item.error}")


# Entry point: start the interactive console tool.
def main() -> None:
    app = SOCConsoleApp()
    app.run()


if __name__ == "__main__":
    main()
