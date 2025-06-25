# bgpview. credits: ChatGPT, GitHub Copilot
from pathlib import Path
import requests
import json
import time
import random
import logging
import os
import subprocess
from typing import List, Optional, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


class Company:
    def __init__(
        self,
        name: str,
        desc_filter: Optional[str] = None,
        filename: Optional[str] = None,
    ):
        """
        :param name: Company name used for ASN search
        :param desc_filter: Optional filter for prefix descriptions (e.g., "oracle")
        :param filename: Optional custom filename for output
        """
        self.name = name
        self.desc_filter = desc_filter
        self.filename = filename

    def output_filename(self) -> str:
        # Always return just the filename, never a path
        if self.filename:
            return os.path.basename(self.filename)
        return self.name.lower().replace(" ", "_") + "_prefixes.json"


HEADERS = {
    "User-Agent": "ruleset updater / (github.com/oklookat/v2ray-rules)",
}


class Hosts:
    def __init__(self, name: str, url: str, output: str):
        self.name = name
        self.url = url
        self.output = output


class HostsCollector:
    def __init__(
        self,
        hosts: List[Hosts],
        output_dir: str = "./rulesets",
        delay: float = 8.0,
    ):
        self.hosts = hosts
        self.output_dir = output_dir
        self.delay = delay
        # Ensure output_dir exists
        os.makedirs(self.output_dir, exist_ok=True)

    def fetch_hosts(self, url: str) -> str:
        response = requests.get(url)
        response.raise_for_status()
        return response.text

    def extract_domains(self, text: str) -> List[str]:
        domains = set()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.add(line)
        return sorted(domains)

    def _build_json(self, domains: List[str]) -> dict:
        return {"version": 3, "rules": [{"domain_suffix": domains}]}

    def run(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        for idx, host in enumerate(self.hosts):
            logging.info(f"\n--- Processing hosts: {host.name} ---")
            # Always resolve output path relative to script directory
            output_path = os.path.normpath(
                os.path.join(script_dir, self.output_dir, host.output)
            )
            try:
                content = self.fetch_hosts(host.url)
                domains = self.extract_domains(content)
                data = self._build_json(domains)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                logging.info(f"Saved {len(domains)} domain(s) to '{output_path}'")
            except Exception as e:
                logging.error(f"Error processing {host.name}: {e}")
                continue

            # Compile ruleset
            try:
                subprocess.run(
                    ["sing-box", "rule-set", "compile", output_path], check=True
                )
                logging.info(f"Compiled ruleset: {output_path}")
            except FileNotFoundError:
                logging.error(
                    "sing-box not found. Please ensure it is installed and in PATH."
                )
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to compile ruleset: {e}")

            # Wait before the next request to avoid hitting rate limits
            if idx < len(self.hosts) - 1:
                try:
                    logging.info(
                        f"[RateLimit] Waiting {self.delay:.1f} seconds before next request..."
                    )
                    time.sleep(random.uniform(self.delay, self.delay))
                except Exception as e:
                    logging.error(f"Error during delay: {e}")
                    continue


class ASNPrefixCollector:
    # FOR COPILOT: dont edit __init__ function name please
    def __init__(
        self,
        companies: List[Company],
        output_dir: str = "./rulesets",
        delay: float = 8.0,
    ):
        self.companies = companies
        self.output_dir = output_dir
        self.delay = delay
        # Ensure output_dir exists
        os.makedirs(self.output_dir, exist_ok=True)

    def run(self):
        for idx, company in enumerate(self.companies):
            logging.info(f"\n--- Processing '{company.name}' ---")
            self._process_company(company)
            # Wait before the next request to avoid hitting rate limits, only if there is a next company
            if idx < len(self.companies) - 1:
                logging.info(
                    f"[RateLimit] Waiting {self.delay:.1f} seconds before next company..."
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
            if not prefixes:
                logging.warning(f"No prefixes found for ASN {asn}")
                continue
            filtered = self._filter_prefixes(prefixes, company.desc_filter)
            if not filtered:
                logging.warning(f"No prefixes matched filter for ASN {asn}")
            all_prefixes.update(filtered)
            logging.info(f"ASN {asn} → {len(filtered)} prefix(es)")
            time.sleep(random.uniform(self.delay, self.delay))

        if not all_prefixes:
            logging.warning(f"No prefixes collected for '{company.name}'")
            return

        # Always join with output_dir and just the filename
        output_path = os.path.join(self.output_dir, company.output_filename())
        self._save_to_json(sorted(all_prefixes), output_path)
        self._compile_ruleset(output_path)

    def _rate_limit_wait(self):
        logging.info(
            f"[RateLimit] Waiting {self.delay:.1f} seconds before next API request..."
        )
        time.sleep(self.delay)

    def _search_asns(self, query: str, retries: int = 3) -> List[int]:
        url = f"https://api.bgpview.io/search?query_term={query}"
        for attempt in range(1, retries + 1):
            self._rate_limit_wait()
            try:
                response = requests.get(url, headers=HEADERS, timeout=10)
                if response.status_code == 429:
                    logging.warning(
                        f"Rate limit hit on ASN search '{query}', waiting {self.delay:.1f}s..."
                    )
                    self._rate_limit_wait()
                    continue
                response.raise_for_status()
                data = response.json()
                return [entry["asn"] for entry in data["data"].get("asns", [])]
            except Exception as e:
                if attempt == retries:
                    logging.error(f"Error searching ASNs for '{query}': {e}")
                    return []
                logging.warning(
                    f"Retrying ASN search '{query}' in {self.delay:.1f}s..."
                )
                self._rate_limit_wait()
        return []

    def _fetch_prefixes(self, asn: int, retries: int = 3) -> List[dict]:
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        for attempt in range(1, retries + 1):
            self._rate_limit_wait()
            try:
                response = requests.get(url, headers=HEADERS, timeout=10)
                if response.status_code == 429:
                    logging.warning(
                        f"Rate limit hit on ASN {asn}, waiting {self.delay:.1f}s..."
                    )
                    self._rate_limit_wait()
                    continue
                response.raise_for_status()
                data = response.json()
                return data["data"].get("ipv4_prefixes", [])
            except Exception as e:
                if attempt == retries:
                    logging.error(f"Failed to fetch prefixes for ASN {asn}: {e}")
                    return []
                logging.warning(f"Retrying ASN {asn} in {self.delay:.1f}s...")
                self._rate_limit_wait()
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

    def _save_to_json(self, cidrs: List[str], output_path: str):
        data = {"version": 3, "rules": [{"ip_cidr": cidrs}]}
        try:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            logging.info(f"Saved {len(cidrs)} prefix(es) to '{output_path}'")
        except Exception as e:
            logging.error(f"Error writing JSON: {e}")

    def _compile_ruleset(self, json_path: str):
        try:
            subprocess.run(["sing-box", "rule-set", "compile", json_path], check=True)
            logging.info(f"Compiled ruleset: {json_path}")
        except FileNotFoundError:
            logging.error(
                "sing-box not found. Please ensure it is installed and in PATH."
            )
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to compile ruleset: {e}")


class DomainListBuilder:
    def __init__(self, url: str, output_path: str):
        self.url = url
        self.output_path = Path(output_path).resolve()
        self.data = {"version": 3, "rules": []}

    def fetch_domains(self):
        response = requests.get(self.url)
        response.raise_for_status()
        domains = response.json()
        if not isinstance(domains, list):
            raise ValueError("Expected a JSON array of domains")
        return domains

    def build_data(self):
        domains = self.fetch_domains()
        self.data["rules"] = [{"domain_suffix": domains}]
        return self.data

    def save_to_file(self):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    def compile_with_singbox(self):
        cmd = ["sing-box", "rule-set", "compile", str(self.output_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"sing-box compile failed:\n{result.stderr}")
        print("Compile successful:\n", result.stdout)

    def run(self):
        self.build_data()
        self.save_to_file()
        self.compile_with_singbox()


# ========================
# COMPANY CONFIGURATION
# ========================


def main():
    geoip_companies = [
        Company(name="reflected", filename="reflected-networks.json"),
        Company(name="cdn77", filename="cdn77.json"),
        Company(name="digitalocean", filename="digital-ocean.json"),
        Company(name="12876", filename="scaleway.json"),
        Company(name="akamai", filename="akamai.json"),
        Company(name="as-vultr", filename="vultr.json"),
        Company(name="stark-industries", filename="stark-industries.json"),
        Company(
            name="oracle",
            desc_filter="oracle corporation",
            filename="oracle.json",
        ),
        Company(
            name="hetzner",
            filename="hetzner.json",
        ),
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

    asn_prefix_collector = ASNPrefixCollector(
        companies=geoip_companies, output_dir="../geoip"
    )
    hosts_collector = HostsCollector(hosts=geosite_hosts, output_dir="../geosite")

    ct_collector = DomainListBuilder(
        "https://reestr.rublacklist.net/api/v3/ct-domains",
        "../geosite/censor-tracker.json",
    )

    # asn_prefix_collector.run()
    # hosts_collector.run()
    ct_collector.run()


if __name__ == "__main__":
    main()
