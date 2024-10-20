import pandas as pd
import requests
import yaml
import os
import concurrent.futures
import ipaddress
from io import StringIO

def is_ip_cidr(address):
    try:
        ipaddress.ip_network(address)
        return True
    except ValueError:
        return False

def read_list_from_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text.splitlines()
    else:
        return None

def parse_and_convert_to_clash(link):
    lines = read_list_from_url(link)
    if lines is None:
        print(f"Failed to fetch data from {link}")
        return None

    clash_rules = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if is_ip_cidr(line):
            clash_rules.append(f"  - IP-CIDR,{line}")
        else:
            clash_rules.append(f"  - DOMAIN-SUFFIX,{line}")

    return clash_rules

def process_link(link):
    try:
        clash_rules = parse_and_convert_to_clash(link)
        if clash_rules:
            output_dir = "./clash_rules"
            os.makedirs(output_dir, exist_ok=True)
            file_name = os.path.join(output_dir, f"{os.path.basename(link).split('.')[0]}.yaml")
            with open(file_name, 'w', encoding='utf-8') as output_file:
                output_file.write("payload:\n")
                output_file.write("\n".join(clash_rules))
            print(f"Successfully processed {link}")
            return file_name
    except Exception as e:
        print(f"Error processing {link}: {str(e)}")
    return None

# 读取 links.txt 中的每个链接并生成对应的 YAML 文件
with open("links.txt", 'r') as links_file:
    links = links_file.read().splitlines()

links = [l for l in links if l.strip() and not l.strip().startswith("#")]

with concurrent.futures.ThreadPoolExecutor() as executor:
    result_file_names = list(executor.map(process_link, links))

result_file_names = [f for f in result_file_names if f]
print("Generated files:")
for file_name in result_file_names:
    print(file_name)
