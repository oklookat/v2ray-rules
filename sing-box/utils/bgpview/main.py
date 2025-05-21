# bgpview. credits: ChatGPT, GitHub Copilot
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

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}


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


class ASNPrefixCollector:
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
        for company in self.companies:
            logging.info(f"\n--- Processing '{company.name}' ---")
            self._process_company(company)

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


# ========================
# COMPANY CONFIGURATION
# ========================


def main():
    companies = [
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
    ]

    collector = ASNPrefixCollector(companies=companies, output_dir="../../geoip")
    collector.run()


if __name__ == "__main__":
    main()
