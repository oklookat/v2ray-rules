# bgpview alternative using RIPE Stat API
# works not so good as BGPView API
import requests
import json
import time
import random
import logging
import os
import subprocess
import threading
from queue import Queue
from typing import List, Optional, Set

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

HEADERS = {
    "User-Agent": "oklookat-bgpview/1.0.0 (https://github.com/oklookat/v2ray-rules-testing)"
}


class Company:
    def __init__(
        self,
        name: str,
        search_term: Optional[str] = None,
        desc_filter: Optional[str] = None,
        filename: Optional[str] = None,
    ):
        self.name = name
        self.search_term = search_term or name
        self.desc_filter = desc_filter
        self.filename = filename
        self.asns: Optional[List[str]] = None  # Will be filled after ASN search

    def output_filename(self) -> str:
        if self.filename:
            return os.path.basename(self.filename)
        return self.name.lower().replace(" ", "_") + "_prefixes.json"


class ASNPrefixCollector:
    def __init__(
        self,
        companies: List[Company],
        output_dir: str = "./rulesets",
        delay: float = 2.0,
    ):
        self.companies = companies
        self.output_dir = output_dir
        self.delay = delay
        os.makedirs(self.output_dir, exist_ok=True)

    def run(self):
        for company in self.companies:
            logging.info(f"\n--- Processing '{company.name}' ---")
            asns = self._search_asns(company.search_term)
            if not asns:
                logging.warning(
                    f"No ASNs found for '{company.name}' (search term: '{company.search_term}'), skipping."
                )
                continue
            company.asns = asns
            self._process_company(company)

    def _search_asns(self, search_term: str) -> List[str]:
        url = f"https://stat.ripe.net/data/searchcomplete/data.json?resource={search_term}"
        try:
            logging.info(
                f"[ASN-SEARCH] Querying RIPE for ASNs with search term: '{search_term}'"
            )
            response = requests.get(url, headers=HEADERS, timeout=10)
            logging.info(
                "[RATE-LIMIT] Waiting 8 seconds to respect RIPE API rate limits..."
            )
            time.sleep(8)  # 8-second rate limit after every request
            response.raise_for_status()
            data = response.json()
            asns = []
            for cat in data.get("data", {}).get("categories", []):
                if cat.get("category") == "ASNs":
                    for suggestion in cat.get("suggestions", []):
                        asn = suggestion.get("value")
                        if asn and asn.startswith("AS"):
                            asns.append(asn)
            logging.info(
                f"[ASN-SEARCH] Found ASNs for '{search_term}': {asns if asns else 'None'}"
            )
            return asns
        except Exception as e:
            logging.error(f"[ASN-SEARCH] Error searching ASNs for '{search_term}': {e}")
            return []

    def _process_company(self, company: Company):
        all_prefixes: Set[str] = set()
        if not company.asns:
            logging.warning(f"No ASNs to process for {company.name}")
            return
        for asn in company.asns:
            prefixes = self._fetch_prefixes(asn, company.desc_filter)
            if not prefixes:
                logging.warning(f"No prefixes found for ASN {asn}")
                continue
            all_prefixes.update(prefixes)
            time.sleep(self.delay)
        if not all_prefixes:
            logging.warning(f"No prefixes found for {company.name}")
            return
        output_path = os.path.join(self.output_dir, company.output_filename())
        self._save_to_json(sorted(all_prefixes), output_path)
        self._compile_ruleset(output_path)

    def _fetch_prefixes(self, asn: str, desc_filter: Optional[str] = None) -> List[str]:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
        try:
            logging.info(f"[PREFIXES] Querying RIPE for prefixes of ASN {asn}")
            response = requests.get(url, headers=HEADERS, timeout=10)
            logging.info(
                f"[RATE-LIMIT] Waiting 8 seconds after announced-prefixes request for ASN {asn}..."
            )
            time.sleep(8)
            response.raise_for_status()
            data = response.json()
            prefixes = []
            prefix_list = []
            for idx, item in enumerate(data["data"].get("prefixes", []), 1):
                family = item.get("family")
                prefix = item.get("prefix")
                if not prefix:
                    continue
                # Only IPv4
                if family is not None and family != 4:
                    continue
                if family is None and ":" in prefix:
                    continue
                prefix_list.append(prefix)
            if not desc_filter:
                prefixes = prefix_list
            else:
                # Use a cache to avoid duplicate prefix-overview requests
                pov_cache = {}

                def worker():
                    while True:
                        idx, prefix = q.get()
                        try:
                            pov_url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={prefix}"
                            logging.info(
                                f"[PREFIXES] [{asn}] Checking prefix {idx}: {prefix} with prefix-overview API..."
                            )
                            pov_resp = requests.get(
                                pov_url, headers=HEADERS, timeout=10
                            )
                            logging.info(
                                f"[RATE-LIMIT] Waiting 8 seconds after prefix-overview request for {prefix}..."
                            )
                            time.sleep(8)
                            pov_resp.raise_for_status()
                            pov_data = pov_resp.json()
                            holder = ""
                            asns = pov_data.get("data", {}).get("asns", [])
                            if asns and isinstance(asns, list):
                                holder = asns[0].get("holder", "")
                            block_desc = (
                                pov_data.get("data", {})
                                .get("block", {})
                                .get("desc", "")
                            )
                            if (
                                desc_filter.lower() in holder.lower()
                                or desc_filter.lower() in block_desc.lower()
                            ):
                                pov_cache[prefix] = True
                            else:
                                logging.info(
                                    f"[PREFIXES] [{asn}] Skipping {prefix} (desc_filter '{desc_filter}' not found in holder/block)"
                                )
                                pov_cache[prefix] = False
                        except Exception as e:
                            logging.error(
                                f"[PREFIXES] Error in prefix-overview for {prefix}: {e}"
                            )
                            pov_cache[prefix] = False
                        finally:
                            q.task_done()

                # Use up to 4 threads (half of RIPE's 8 concurrent limit for safety)
                q = Queue()
                threads = []
                for _ in range(4):
                    t = threading.Thread(target=worker, daemon=True)
                    t.start()
                    threads.append(t)
                for idx, prefix in enumerate(prefix_list, 1):
                    q.put((idx, prefix))
                q.join()
                prefixes = [p for p in prefix_list if pov_cache.get(p)]
            logging.info(
                f"[PREFIXES] ASN {asn}: {len(prefixes)} IPv4 prefix(es) found after filtering"
            )
            return prefixes
        except Exception as e:
            logging.error(f"[PREFIXES] Error fetching prefixes for {asn}: {e}")
            return []

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


def main():
    companies = [
        # Company(name="reflected", filename="reflected-networks.json"),
        # Company(name="cdn77", filename="cdn77.json"),
        # Company(name="digitalocean", filename="digital-ocean.json"),
        # Company(name="12876", filename="scaleway.json"),
        # Company(name="akamai", filename="akamai.json"),
        Company(name="AS-CHOOPA", desc_filter="Vultr", filename="vultr.json"),
        # Company(name="stark-industries", filename="stark-industries.json"),
        # Company(
        #     name="oracle",
        #     desc_filter="oracle corporation",
        #     filename="oracle.json",
        # ),
    ]
    collector = ASNPrefixCollector(companies=companies, output_dir="../../geoipd")
    collector.run()


if __name__ == "__main__":
    main()
