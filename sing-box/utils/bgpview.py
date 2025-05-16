import requests
import json
import time

def get_asns_for_company(company_name):
    """Ищет все ASN, связанные с названием компании через API bgpview.io"""
    url = f"https://api.bgpview.io/search?query_term={company_name}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    if data.get("status") != "ok":
        raise Exception("Ошибка в ответе API при поиске ASN")
    return [asn_entry["asn"] for asn_entry in data["data"].get("asns", [])]

def get_ipv4_cidrs_for_asn(asn):
    """Получает все IPv4-префиксы, связанные с конкретным ASN"""
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    if data.get("status") != "ok":
        raise Exception(f"Ошибка в ответе API при получении префиксов ASN {asn}")
    return [entry["prefix"] for entry in data["data"].get("ipv4_prefixes", [])]

def gather_all_ipv4_cidrs(company_name, delay=1.5):
    """Ищет все ASN по названию компании и собирает все IPv4-префиксы"""
    all_cidrs = set()
    asns = get_asns_for_company(company_name)
    print(f"[INFO] Найдено {len(asns)} ASN для {company_name}")
    for asn in asns:
        try:
            print(f"[INFO] Обработка ASN {asn}")
            cidrs = get_ipv4_cidrs_for_asn(asn)
            all_cidrs.update(cidrs)
            time.sleep(delay)  # Уважение к API
        except Exception as e:
            print(f"[ERROR] Ошибка при ASN {asn}: {e}")
    return sorted(all_cidrs)

def save_cidrs_to_json(cidrs, filename="output.json"):
    result = {
        "version": 3,
        "rules": [
            {
                "ip_cidr": cidrs
            }
        ]
    }
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)
    print(f"[SUCCESS] Сохранено {len(cidrs)} префиксов в файл {filename}")

# Пример использования:
if __name__ == "__main__":
    company_name = input("Введите название компании: ").strip()
    cidrs = gather_all_ipv4_cidrs(company_name)
    save_cidrs_to_json(cidrs, f"{company_name.lower().replace(' ', '_')}_prefixes.json")