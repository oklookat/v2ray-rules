# bgpview / ruleset updater
# Credits: ChatGPT, GitHub Copilot
from pathlib import Path
import requests
import json
import time
import random
import logging
import os
import subprocess
from typing import List, Optional, Set

import tldextract

# -----------------------------
# Logging Configuration
# -----------------------------
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


# -----------------------------
# Company Class
# -----------------------------
class Company:
    def __init__(
        self,
        name: str,
        desc_filter: Optional[str] = None,
        filename: Optional[str] = None,
    ):
        """
        :param name: Company name for ASN search
        :param desc_filter: Optional filter for prefix descriptions (e.g., "oracle")
        :param filename: Optional custom filename for output
        """
        self.name = name
        self.desc_filter = desc_filter
        self.filename = filename

    def output_filename(self) -> str:
        """Return a safe filename for output JSON."""
        if self.filename:
            return os.path.basename(self.filename)
        return f"{self.name.lower().replace(' ', '_')}_prefixes.json"


# -----------------------------
# HTTP Request Headers
# -----------------------------
HEADERS = {
    "User-Agent": "ruleset-updater (github.com/oklookat/v2ray-rules)",
}


# -----------------------------
# Hosts Management
# -----------------------------
class Hosts:
    def __init__(self, name: str, url: str, output: str):
        self.name = name
        self.url = url
        self.output = output


class HostsCollector:
    def __init__(
        self, hosts: List[Hosts], output_dir: str = "./rulesets", delay: float = 8.0
    ):
        self.hosts = hosts
        self.output_dir = output_dir
        self.delay = delay
        os.makedirs(self.output_dir, exist_ok=True)

    def fetch_hosts(self, url: str) -> str:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        return response.text

    def extract_domains(self, text: str) -> List[str]:
        return sorted(
            {
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.startswith("#")
            }
        )

    def _build_json(self, domains: List[str]) -> dict:
        return {"version": 3, "rules": [{"domain_suffix": domains}]}

    def run(self):
        script_dir = Path(__file__).resolve().parent
        for idx, host in enumerate(self.hosts):
            logging.info(f"\n--- Processing hosts: {host.name} ---")
            output_path = script_dir / self.output_dir / host.output

            try:
                content = self.fetch_hosts(host.url)
                domains = self.extract_domains(content)
                data = self._build_json(domains)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                logging.info(f"Saved {len(domains)} domain(s) to '{output_path}'")
            except Exception as e:
                logging.error(f"Error processing {host.name}: {e}")
                continue

            # Compile ruleset with sing-box
            try:
                subprocess.run(
                    ["sing-box", "rule-set", "compile", str(output_path)], check=True
                )
                logging.info(f"Compiled ruleset: {output_path}")
            except FileNotFoundError:
                logging.error(
                    "sing-box not found. Please ensure it is installed and in PATH."
                )
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to compile ruleset: {e}")

            if idx < len(self.hosts) - 1:
                logging.info(
                    f"[RateLimit] Waiting {self.delay:.1f}s before next request..."
                )
                time.sleep(random.uniform(self.delay, self.delay))


# -----------------------------
# ASN Prefix Collector
# -----------------------------
class ASNPrefixCollector:
    def __init__(
        self,
        companies: List[Company],
        output_dir: str = "./rulesets",
        delay: float = 8.0,
    ):
        self.companies = companies
        self.output_dir = Path(output_dir).resolve()
        self.delay = delay
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self):
        for idx, company in enumerate(self.companies):
            logging.info(f"\n--- Processing '{company.name}' ---")
            self._process_company(company)
            if idx < len(self.companies) - 1:
                logging.info(
                    f"[RateLimit] Waiting {self.delay:.1f}s before next company..."
                )
                time.sleep(random.uniform(self.delay, self.delay))

    def _process_company(self, company: Company):
        asns = self._search_asns(company.name)
        if not asns:
            logging.warning(f"No ASNs found for '{company.name}'")
            return

        all_prefixes: Set[str] = set()
        for asn in asns:
            logging.info(f"Fetching prefixes for ASN {asn}")
            prefixes = self._fetch_prefixes(asn)
            filtered = self._filter_prefixes(prefixes, company.desc_filter)
            all_prefixes.update(filtered)
            logging.info(f"ASN {asn} → {len(filtered)} prefix(es)")
            time.sleep(random.uniform(self.delay, self.delay))

        if not all_prefixes:
            logging.warning(f"No prefixes collected for '{company.name}'")
            return

        output_path = self.output_dir / company.output_filename()
        self._save_to_json(sorted(all_prefixes), output_path)
        self._compile_ruleset(output_path)

    def _rate_limit_wait(self):
        time.sleep(self.delay)

    def _search_asns(self, query: str, retries: int = 3) -> List[int]:
        url = f"https://api.bgpview.io/search?query_term={query}"
        for attempt in range(retries):
            self._rate_limit_wait()
            try:
                resp = requests.get(url, headers=HEADERS, timeout=10)
                if resp.status_code == 429:
                    logging.warning(
                        f"Rate limit hit on '{query}', retrying after {self.delay}s..."
                    )
                    self._rate_limit_wait()
                    continue
                resp.raise_for_status()
                data = resp.json()
                return [entry["asn"] for entry in data["data"].get("asns", [])]
            except Exception as e:
                if attempt == retries - 1:
                    logging.error(f"ASN search failed for '{query}': {e}")
                    return []
        return []

    def _fetch_prefixes(self, asn: int, retries: int = 3) -> List[dict]:
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        for attempt in range(retries):
            self._rate_limit_wait()
            try:
                resp = requests.get(url, headers=HEADERS, timeout=10)
                if resp.status_code == 429:
                    logging.warning(
                        f"Rate limit hit on ASN {asn}, retrying after {self.delay}s..."
                    )
                    self._rate_limit_wait()
                    continue
                resp.raise_for_status()
                return resp.json()["data"].get("ipv4_prefixes", [])
            except Exception as e:
                if attempt == retries - 1:
                    logging.error(f"Failed to fetch prefixes for ASN {asn}: {e}")
                    return []
        return []

    def _filter_prefixes(
        self, prefixes: List[dict], desc_filter: Optional[str]
    ) -> List[str]:
        if not desc_filter:
            return [p["prefix"] for p in prefixes]
        desc_filter_lower = desc_filter.lower()
        return [
            p["prefix"]
            for p in prefixes
            if desc_filter_lower in (p.get("description") or "").lower()
        ]

    def _save_to_json(self, cidrs: List[str], output_path: Path):
        data = {"version": 3, "rules": [{"ip_cidr": cidrs}]}
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            logging.info(f"Saved {len(cidrs)} prefix(es) to '{output_path}'")
        except Exception as e:
            logging.error(f"Error writing JSON: {e}")

    def _compile_ruleset(self, json_path: Path):
        try:
            subprocess.run(
                ["sing-box", "rule-set", "compile", str(json_path)], check=True
            )
            logging.info(f"Compiled ruleset: {json_path}")
        except FileNotFoundError:
            logging.error(
                "sing-box not found. Please ensure it is installed and in PATH."
            )
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to compile ruleset: {e}")


# -----------------------------
# Domain List Builder
# -----------------------------


class DomainListBuilder:
    def __init__(self, url: str, output_path: str):
        self.url = url
        self.output_path = Path(output_path).resolve()
        self.data = {"version": 3, "rules": []}

    def fetch_domains(self) -> List[str]:
        resp = requests.get(self.url, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        domains = resp.json()
        if not isinstance(domains, list):
            raise ValueError("Expected a JSON array of domains")
        return domains

    def normalize_domains(self, domains: List[str]) -> List[str]:
        """
        Removes subdomains, leaving only the root domain (eg hello.world.com → world.com).
        """
        root_domains = set()
        for d in domains:
            d = d.strip().lower()
            if not d:
                continue
            ext = tldextract.extract(d)
            if not ext.domain or not ext.suffix:
                continue
            root_domains.add(f"{ext.domain}.{ext.suffix}")
        return sorted(root_domains)

    def build_data(self):
        domains = self.fetch_domains()
        normalized = self.normalize_domains(domains)
        self.data["rules"] = [{"domain_suffix": normalized}]

    def save_to_file(self):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    def compile_with_singbox(self):
        cmd = ["sing-box", "rule-set", "compile", str(self.output_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"sing-box compile failed:\n{result.stderr}")
        logging.info(f"Compile successful:\n{result.stdout}")

    def run(self):
        self.build_data()
        self.save_to_file()
        self.compile_with_singbox()


# -----------------------------
# Main Function
# -----------------------------
def main():
    geoip_companies = [
        Company(name="reflected", filename="reflected-networks.json"),
        Company(name="cdn77", filename="cdn77.json"),
        Company(name="digitalocean", filename="digital-ocean.json"),
        Company(name="12876", filename="scaleway.json"),
        Company(name="akamai", filename="akamai.json"),
        Company(name="as-vultr", filename="vultr.json"),
        Company(name="THE-HOSTING", filename="stark-industries.json"),
        Company(
            name="oracle", desc_filter="oracle corporation", filename="oracle.json"
        ),
        Company(name="hetzner", filename="hetzner.json"),
        Company(
            name="cloudflare", desc_filter="cloudflare", filename="cloudflare.json"
        ),
        Company(name="DEAC-AS", filename="deac.json"),
    ]

    geosite_hosts = [
        Hosts(
            name="no-russia",
            url="https://github.com/oklookat/no-russia-hosts/raw/refs/heads/main/hosts.txt",
            output="no-russia.json",
        ),
    ]

    ASNPrefixCollector(companies=geoip_companies, output_dir="../geoip").run()
    HostsCollector(hosts=geosite_hosts, output_dir="../geosite").run()
    DomainListBuilder(
        "https://reestr.rublacklist.net/api/v3/ct-domains",
        "../geosite/censor-tracker.json",
    ).run()


if __name__ == "__main__":
    main()
