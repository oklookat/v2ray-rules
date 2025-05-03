import csv
import json
import ipaddress

def extract_ipv4_cidrs(csv_filename, json_filename):
    ipv4_cidrs = []

    with open(csv_filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if not row:
                continue  # пропустить пустую строку
            cidr_str = row[0].strip()
            try:
                net = ipaddress.ip_network(cidr_str, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    ipv4_cidrs.append(str(net))
            except ValueError:
                # Невалидная CIDR запись — пропускаем
                continue

    # Формируем JSON
    output = {
        "version": 3,
        "rules": [
            {
                "ip_cidr": ipv4_cidrs
            }
        ]
    }

    # Сохраняем в файл
    with open(json_filename, 'w') as jsonfile:
        json.dump(output, jsonfile, indent=4)

# Пример запуска
extract_ipv4_cidrs("google.csv", "digital-ocean.json")