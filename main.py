import requests
import os
import concurrent.futures
import ipaddress

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

def clean_rules(lines):
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith('#')
    ]

def parse_and_convert_to_clash(lines):
    clash_rules = []
    for line in clean_rules(lines):
        if is_ip_cidr(line):
            clash_rules.append(f"  - IP-CIDR,{line}")
        else:
            clash_rules.append(f"  - DOMAIN-SUFFIX,{line}")

    return clash_rules

def process_link(link):
    try:
        lines = read_list_from_url(link)
        if lines is None:
            print(f"Failed to fetch data from {link}")
            return []

        rules = clean_rules(lines)
        if not rules:
            return []

        output_dir = "./clash_rules"
        os.makedirs(output_dir, exist_ok=True)
        base_name = os.path.basename(link).split('.')[0]
        generated_files = []

        clash_rules = parse_and_convert_to_clash(lines)
        yaml_file_name = os.path.join(output_dir, f"{base_name}.yaml")
        with open(yaml_file_name, 'w', encoding='utf-8') as output_file:
            output_file.write("payload:\n")
            output_file.write("\n".join(clash_rules))
        generated_files.append(yaml_file_name)

        # IP 规则额外保留原始 CIDR 文本，供 mihomo ipcidr provider 和 sing-box 转换使用。
        if all(is_ip_cidr(rule) for rule in rules):
            txt_file_name = os.path.join(output_dir, f"{base_name}.txt")
            with open(txt_file_name, 'w', encoding='utf-8') as output_file:
                output_file.write("\n".join(rules))
                output_file.write("\n")
            generated_files.append(txt_file_name)

        print(f"Successfully processed {link}")
        return generated_files
    except Exception as e:
        print(f"Error processing {link}: {str(e)}")
    return []

# 读取 links.txt 中的每个链接并生成对应的 YAML 文件
with open("links.txt", 'r') as links_file:
    links = links_file.read().splitlines()

links = [l for l in links if l.strip() and not l.strip().startswith("#")]

with concurrent.futures.ThreadPoolExecutor() as executor:
    result_file_names = [
        file_name
        for file_names in executor.map(process_link, links)
        for file_name in file_names
    ]

print("Generated files:")
for file_name in result_file_names:
    print(file_name)
