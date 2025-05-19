import requests
import json
import time
import random
import logging
import argparse
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)

# Default headers
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

def get_asns_for_company(company_name):
    """Searches for ASNs associated with a company using the bgpview.io API"""
    url = f"https://api.bgpview.io/search?query_term={company_name}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "ok":
            raise Exception("Invalid API response status")
        return [asn_entry["asn"] for asn_entry in data["data"].get("asns", [])]
    except Exception as e:
        logging.error(f"Failed to search ASNs for '{company_name}': {e}")
        return []

def get_ipv4_cidrs_for_asn(asn, retries=3):
    """Fetches all IPv4 prefixes associated with an ASN, with retry on 429"""
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            if response.status_code == 429:
                wait = random.uniform(5, 10)
                logging.warning(f"Rate limited (429) on ASN {asn}. Waiting {wait:.1f}s (attempt {attempt}/{retries})...")
                time.sleep(wait)
                continue
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "ok":
                raise Exception("Invalid API response status")
            logging.debug(f"Successfully fetched prefixes for ASN {asn}")
            return [entry["prefix"] for entry in data["data"].get("ipv4_prefixes", [])]
        except Exception as e:
            if attempt == retries:
                logging.error(f"Failed to fetch prefixes for ASN {asn}: {e}")
                return []
            wait = random.uniform(2, 4)
            logging.warning(f"Retrying ASN {asn} after {wait:.1f}s (attempt {attempt}/{retries})...")
            time.sleep(wait)

def gather_all_ipv4_cidrs(company_name, min_delay=1.5, max_delay=3.0):
    """Finds all ASNs for a company and gathers their IPv4 prefixes"""
    all_cidrs = set()
    asns = get_asns_for_company(company_name)
    if not asns:
        logging.warning("No ASNs found. Aborting.")
        return []

    logging.info(f"Found {len(asns)} ASN(s) for '{company_name}'")

    for asn in asns:
        logging.info(f"Processing ASN {asn}")
        cidrs = get_ipv4_cidrs_for_asn(asn)
        if cidrs:
            all_cidrs.update(cidrs)
            logging.info(f"ASN {asn} → {len(cidrs)} prefix(es) added")
        else:
            logging.warning(f"ASN {asn} returned no prefixes.")
        delay = random.uniform(min_delay, max_delay)
        logging.debug(f"Sleeping for {delay:.2f} seconds")
        time.sleep(delay)
    return sorted(all_cidrs)

def save_cidrs_to_json(cidrs, output_path):
    """Saves the collected CIDRs to a JSON file"""
    result = {
        "version": 3,
        "rules": [
            {
                "ip_cidr": cidrs
            }
        ]
    }
    try:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result, f, indent=4)
        logging.info(f"Saved {len(cidrs)} prefix(es) to file: {output_path}")
    except Exception as e:
        logging.error(f"Failed to save output file: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="Fetch IPv4 prefixes for all ASNs associated with a company.")
    parser.add_argument("company", help="Company name to search for ASNs")
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file path (default: <company>_prefixes.json)",
        default=None
    )
    parser.add_argument(
        "--min-delay", type=float, default=1.5,
        help="Minimum delay between API requests in seconds (default: 1.5)"
    )
    parser.add_argument(
        "--max-delay", type=float, default=3.0,
        help="Maximum delay between API requests in seconds (default: 3.0)"
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    company_name = args.company.strip()
    if not company_name:
        logging.critical("Company name must not be empty.")
        exit(1)

    output_file = args.output or f"{company_name.lower().replace(' ', '_')}_prefixes.json"

    cidrs = gather_all_ipv4_cidrs(company_name, min_delay=args.min_delay, max_delay=args.max_delay)
    if cidrs:
        save_cidrs_to_json(cidrs, output_file)
    else:
        logging.warning("No prefixes found.")
