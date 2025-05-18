import requests
import json

GITHUB_URL = "https://raw.githubusercontent.com/dartraiden/no-russia-hosts/refs/heads/master/hosts.txt"
OUTPUT_FILE = "no-russia.json"

def fetch_domain_list(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text

def extract_domains(text):
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.add(line)
    return sorted(domains)

def build_json(domains):
    return {
        "version": 3,
        "rules": [
            {
                "domain_keyword": domains
            }
        ]
    }

def main():
    content = fetch_domain_list(GITHUB_URL)
    domains = extract_domains(content)
    data = build_json(domains)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"Сохранено {len(domains)} доменов в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
