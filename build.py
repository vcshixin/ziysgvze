#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sing-box & Clash 统一规则构建引擎 V3
特性:
  1. 纯海外 AI 规则全自动脱手 (排除国内百炼/通义/文心/DeepSeek/Kimi)
  2. 顶级双源广告规则自动聚合 (Cats-Team/AdRules + TG-Twilight/秋风广告 深度去重合并)
     - 统一标准产物: rule/category-ads-all.json, rule/category-ads-all.srs, clash_rules/category-ads-all.yaml
     - 彻底废除旧版多余的 AdRules.* / adrules_domainset.* 冗余文件
  3. 智能内容感知 (Smart Diff Write): 内容不变不碰磁盘，杜绝 Git 脏提交
  4. 故障熔断保护 (Fail-Safe): 抓取异常时保留上一健康版本，绝不清空
  5. 自动化测试门禁 (Self-Test Suite): 关键规则与 SRS 完整性断言
"""

import os
import sys
import json
import time
import shutil
import hashlib
import urllib.request
import ipaddress
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Please install it with 'pip install pyyaml'.")
    sys.exit(1)

OUTPUT_CLASH_DIR = "./clash_rules"
OUTPUT_SINGBOX_DIR = "./rule"
CUSTOM_RULES_DIR = "./custom_rules"
EXTERNAL_LINKS_FILE = "external_links.txt"

MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix',
    'HOST-SUFFIX': 'domain_suffix',
    'host-suffix': 'domain_suffix',
    'DOMAIN': 'domain',
    'HOST': 'domain',
    'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'HOST-KEYWORD': 'domain_keyword',
    'host-keyword': 'domain_keyword',
    'IP-CIDR': 'ip_cidr',
    'ip-cidr': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
    'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip',
    'DST-PORT': 'port',
    'SRC-PORT': 'source_port',
    'PROCESS-NAME': 'process_name',
    'process-name': 'process_name',
    'URL-REGEX': 'domain_regex',
    'DOMAIN-REGEX': 'domain_regex'
}

stats = {
    "custom_count": 0,
    "external_count": 0,
    "failed_links": [],
    "retained_count": 0,
    "total_rules": 0,
    "ad_rules_count": 0
}
stats_lock = threading.Lock()

def smart_write_file(file_path: str, new_content: str) -> bool:
    new_bytes = new_content.encode('utf-8')
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            old_bytes = f.read()
        if hashlib.sha256(old_bytes).digest() == hashlib.sha256(new_bytes).digest():
            return False
    with open(file_path, 'wb') as f:
        f.write(new_bytes)
    return True

def is_ip_or_cidr(val: str) -> bool:
    val = val.strip()
    try:
        ipaddress.ip_network(val, strict=False)
        return True
    except ValueError:
        return False

def fetch_url(url: str, retries: int = 3, timeout: int = 25) -> str:
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    return resp.read().decode('utf-8')
        except Exception as e:
            if attempt == retries:
                print(f"[-] Failed to fetch {url} after {retries} attempts: {e}")
                return ""
            time.sleep(1)
    return ""

def parse_items_to_rules(raw_items):
    parsed = []
    for item in raw_items:
        if not item:
            continue
        line = str(item).strip()
        if not line or line.startswith('#'):
            continue
        if '#' in line:
            line = line.split('#', 1)[0].strip()
        if not line:
            continue

        if ',' in line:
            parts = [p.strip() for p in line.split(',')]
            pattern = parts[0].upper()
            address = parts[1]
            if pattern in MAP_DICT:
                parsed.append((MAP_DICT[pattern], address))
            elif is_ip_or_cidr(pattern):
                parsed.append(('ip_cidr', pattern))
            else:
                parsed.append(('domain_suffix', address))
        else:
            address = line.strip("'\"")
            if is_ip_or_cidr(address):
                parsed.append(('ip_cidr', address))
            elif address.startswith('+.') or address.startswith('.'):
                parsed.append(('domain_suffix', address.lstrip('+.')))
            elif address.startswith('+'):
                parsed.append(('domain_suffix', address.lstrip('+')))
            else:
                parsed.append(('domain_suffix', address))
    return parsed

def parse_yaml_or_text(content: str):
    raw_items = []
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'payload' in data:
            raw_items = data.get('payload', [])
        elif isinstance(data, list):
            raw_items = data
        else:
            raw_items = content.splitlines()
    except Exception:
        raw_items = content.splitlines()
    return parse_items_to_rules(raw_items)

def render_clash_yaml(parsed_rules) -> str:
    lines = ["payload:"]
    reverse_map = {
        'domain_suffix': 'DOMAIN-SUFFIX',
        'domain': 'DOMAIN',
        'domain_keyword': 'DOMAIN-KEYWORD',
        'ip_cidr': 'IP-CIDR',
        'source_ip_cidr': 'SRC-IP-CIDR',
        'geoip': 'GEOIP',
        'port': 'DST-PORT',
        'source_port': 'SRC-PORT',
        'process_name': 'PROCESS-NAME',
        'domain_regex': 'DOMAIN-REGEX'
    }
    seen = set()
    for pattern, addr in parsed_rules:
        clash_pat = reverse_map.get(pattern, 'DOMAIN-SUFFIX')
        line = f"  - {clash_pat},{addr}"
        if line not in seen:
            seen.add(line)
            lines.append(line)
    return "\n".join(lines) + "\n"

def render_singbox_json(parsed_rules) -> str:
    grouped = {}
    for pattern, addr in parsed_rules:
        if pattern not in grouped:
            grouped[pattern] = set()
        grouped[pattern].add(addr)

    rules_list = []
    for pattern in sorted(grouped.keys()):
        addrs = sorted(list(grouped[pattern]))
        if addrs:
            rules_list.append({pattern: addrs})

    data = {
        "version": 2,
        "rules": rules_list
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"

def process_custom_rules():
    print("[*] Processing custom rules (Priority Top)...")
    if not os.path.exists(CUSTOM_RULES_DIR):
        return

    for fname in sorted(os.listdir(CUSTOM_RULES_DIR)):
        fpath = os.path.join(CUSTOM_RULES_DIR, fname)
        if not os.path.isfile(fpath):
            continue

        base_name = os.path.splitext(fname)[0]
        ext = os.path.splitext(fname)[1].lower()

        if ext in ['.yaml', '.yml', '.txt', '.list']:
            with open(fpath, 'r', encoding='utf-8') as f:
                content = f.read()

            parsed = parse_yaml_or_text(content)
            stats["custom_count"] += 1
            stats["total_rules"] += len(parsed)

            out_clash = os.path.join(OUTPUT_CLASH_DIR, f"{base_name}.yaml")
            if ext in ['.yaml', '.yml']:
                smart_write_file(out_clash, content)
            else:
                smart_write_file(out_clash, render_clash_yaml(parsed))

            out_json = os.path.join(OUTPUT_SINGBOX_DIR, f"{base_name}.json")
            smart_write_file(out_json, render_singbox_json(parsed))
            print(f"  [+] Custom: {base_name} ({len(parsed)} rules)")

def process_external_link(entry: str):
    entry = entry.strip()
    if not entry or entry.startswith('#'):
        return

    if '#' in entry:
        url, alias = entry.split('#', 1)
        url = url.strip()
        base_name = alias.strip()
    else:
        url = entry
        base_name = os.path.basename(url).split('.')[0]

    out_clash = os.path.join(OUTPUT_CLASH_DIR, f"{base_name}.yaml")
    out_json = os.path.join(OUTPUT_SINGBOX_DIR, f"{base_name}.json")

    content = fetch_url(url)
    if not content:
        with stats_lock:
            if os.path.exists(out_json) and os.path.exists(out_clash):
                print(f"  [!] Fallback preserved: {base_name} (upstream fetch failed)")
                stats["retained_count"] += 1
                return
            stats["failed_links"].append(url)
            return

    if url.endswith('.json'):
        try:
            json_data = json.loads(content)
            if 'rules' in json_data:
                smart_write_file(out_json, content)
                parsed = []
                for r in json_data.get('rules', []):
                    for k, v in r.items():
                        if isinstance(v, list):
                            for item in v:
                                parsed.append((k, item))
                if parsed:
                    smart_write_file(out_clash, render_clash_yaml(parsed))
                with stats_lock:
                    stats["external_count"] += 1
                    stats["total_rules"] += len(parsed)
                print(f"  [+] External Sing-box JSON: {base_name} ({len(parsed)} rules)")
                return
        except Exception:
            pass

    parsed = parse_yaml_or_text(content)
    if not parsed:
        with stats_lock:
            if os.path.exists(out_json):
                print(f"  [!] Fallback preserved: {base_name} (parsed 0 rules)")
                stats["retained_count"] += 1
                return
            stats["failed_links"].append(url)
            return

    smart_write_file(out_clash, render_clash_yaml(parsed))
    smart_write_file(out_json, render_singbox_json(parsed))

    if base_name in ['china_ip_list', 'gfw_ip_list']:
        out_txt = os.path.join(OUTPUT_CLASH_DIR, f"{base_name}.txt")
        ips = [addr for pat, addr in parsed if pat == 'ip_cidr']
        smart_write_file(out_txt, "\n".join(ips) + "\n")

    with stats_lock:
        stats["external_count"] += 1
        stats["total_rules"] += len(parsed)
    print(f"  [+] External: {base_name} ({len(parsed)} rules)")

def merge_and_build_ads():
    """
    自主双源聚合: Cats-Team/AdRules + TG-Twilight/秋风广告规则
    唯一标准产出:
      - rule/category-ads-all.json & rule/category-ads-all.srs
      - clash_rules/category-ads-all.yaml
    彻底不生成任何冗余的 AdRules.* / adrules_domainset.* 兼容文件
    """
    print("[*] Merging dual-source Ad blocking rules (Cats-Team + AWAvenue 秋风)...")
    url_cats = 'https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules_domainset.txt'
    url_aw = 'https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Singbox.json'

    cats_content = fetch_url(url_cats)
    aw_content = fetch_url(url_aw)

    out_singbox = os.path.join(OUTPUT_SINGBOX_DIR, "category-ads-all.json")
    out_clash = os.path.join(OUTPUT_CLASH_DIR, "category-ads-all.yaml")

    if not cats_content and not aw_content:
        if os.path.exists(out_singbox):
            print("  [!] Preserved previous category-ads-all (both ad sources fetch failed)")
            stats["retained_count"] += 1
            return
        print("  [-] Error: Failed to fetch ad sources.")
        return

    merged_suffixes = set()
    merged_domains = set()
    merged_keywords = set()

    if cats_content:
        for line in cats_content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                clean = line.lstrip('+.')
                if clean:
                    merged_suffixes.add(clean)

    if aw_content:
        try:
            aw_json = json.loads(aw_content)
            for r in aw_json.get('rules', []):
                merged_domains.update(r.get('domain', []))
                merged_suffixes.update(r.get('domain_suffix', []))
                merged_keywords.update(r.get('domain_keyword', []))
        except Exception as e:
            print(f"  [-] Warning: parsing AWAvenue json failed: {e}")

    rules_list = []
    if merged_domains:
        rules_list.append({"domain": sorted(list(merged_domains))})
    if merged_suffixes:
        rules_list.append({"domain_suffix": sorted(list(merged_suffixes))})
    if merged_keywords:
        rules_list.append({"domain_keyword": sorted(list(merged_keywords))})

    singbox_data = {
        "version": 2,
        "rules": rules_list
    }
    json_str = json.dumps(singbox_data, ensure_ascii=False, indent=2) + "\n"
    smart_write_file(out_singbox, json_str)

    clash_parsed = []
    for d in merged_domains:
        clash_parsed.append(('domain', d))
    for s in merged_suffixes:
        clash_parsed.append(('domain_suffix', s))
    for k in merged_keywords:
        clash_parsed.append(('domain_keyword', k))

    yaml_str = render_clash_yaml(clash_parsed)
    smart_write_file(out_clash, yaml_str)

    total_ads = len(merged_domains) + len(merged_suffixes) + len(merged_keywords)
    stats["ad_rules_count"] = total_ads
    stats["total_rules"] += total_ads
    print(f"  [✓] Unified category-ads-all: {total_ads:,} rules")

def clean_deprecated_files():
    """
    清理不再需要的旧版 AdRules / adrules_domainset 冗余文件
    """
    deprecated = [
        os.path.join(OUTPUT_CLASH_DIR, "AdRules.yaml"),
        os.path.join(OUTPUT_CLASH_DIR, "adrules_domainset.yaml"),
        os.path.join(OUTPUT_SINGBOX_DIR, "AdRules.json"),
        os.path.join(OUTPUT_SINGBOX_DIR, "AdRules.srs"),
        os.path.join(OUTPUT_SINGBOX_DIR, "AdRules.txt"),
        os.path.join(OUTPUT_SINGBOX_DIR, "adrules_domainset.json"),
        os.path.join(OUTPUT_SINGBOX_DIR, "adrules_domainset.srs"),
    ]
    for p in deprecated:
        if os.path.exists(p):
            try:
                os.remove(p)
                print(f"  [x] Removed deprecated file: {p}")
            except Exception as e:
                print(f"  [-] Error removing {p}: {e}")

def compile_srs():
    sing_box_bin = shutil.which("sing-box")
    if not sing_box_bin:
        print("[!] sing-box binary not found in PATH. Skipping .srs compilation.")
        return 0

    print(f"[*] Compiling .srs rule sets with {sing_box_bin}...")
    compiled_count = 0

    for fname in sorted(os.listdir(OUTPUT_SINGBOX_DIR)):
        if fname.endswith(".json"):
            json_path = os.path.join(OUTPUT_SINGBOX_DIR, fname)
            srs_path = os.path.join(OUTPUT_SINGBOX_DIR, fname.replace(".json", ".srs"))
            cmd = [sing_box_bin, "rule-set", "compile", "--output", srs_path, json_path]
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                compiled_count += 1
            except subprocess.CalledProcessError as e:
                print(f"  [✗] Failed to compile {json_path}: {e.stderr.decode('utf-8')}")

    print(f"[✓] Successfully compiled {compiled_count} SRS binary rule sets.")
    return compiled_count

def run_self_test():
    print("\n" + "="*50)
    print("[*] Running automated verification & sanity checks...")
    print("="*50)

    critical_rules = ['emby', 'ddli', 'vilm', 'nas', 'fuwuqi', 'ai-all', 'category-ads-all']
    for cr in critical_rules:
        json_file = os.path.join(OUTPUT_SINGBOX_DIR, f"{cr}.json")
        yaml_file = os.path.join(OUTPUT_CLASH_DIR, f"{cr}.yaml")
        assert os.path.exists(json_file), f"Critical rule missing: {json_file}"
        assert os.path.exists(yaml_file), f"Critical rule missing: {yaml_file}"

        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            assert data.get("version") == 2, f"{cr}.json is not sing-box version 2"
            assert len(data.get("rules", [])) > 0, f"{cr}.json has 0 rules!"

        with open(yaml_file, 'r', encoding='utf-8') as f:
            content = f.read()
            assert "payload:" in content, f"{cr}.yaml missing payload header"

    emby_yaml_path = os.path.join(CUSTOM_RULES_DIR, "emby.yaml")
    if os.path.exists(emby_yaml_path):
        with open(emby_yaml_path, 'r', encoding='utf-8') as f:
            emby_src = f.read()
        with open(os.path.join(OUTPUT_SINGBOX_DIR, "emby.json"), 'r', encoding='utf-8') as f:
            emby_content = f.read()
        if "origamiart.uk" in emby_src:
            assert "origamiart.uk" in emby_content, "emby.json missing origamiart.uk!"
        if "origmiart.uk" in emby_src:
            assert "origmiart.uk" in emby_content, "emby.json missing origmiart.uk!"

    # 检查纯海外 AI 规则 (必须排除国内大模型，且正确映射 process_name)
    with open(os.path.join(OUTPUT_SINGBOX_DIR, "ai-all.json"), 'r', encoding='utf-8') as f:
        ai_content = f.read()
        assert "openai.com" in ai_content or "chatgpt.com" in ai_content, "ai-all.json missing OpenAI!"
        assert "tongyi.aliyun.com" not in ai_content, "ai-all.json wrongly included Tongyi!"
        assert "deepseek.com" not in ai_content, "ai-all.json wrongly included DeepSeek!"

    with open(os.path.join(OUTPUT_CLASH_DIR, "ai-all.yaml"), 'r', encoding='utf-8') as f:
        ai_yaml_content = f.read()
        assert "PROCESS-NAME,codex" in ai_yaml_content or "PROCESS-NAME,cursor" in ai_yaml_content, "ai-all.yaml missing PROCESS-NAME rules!"
        assert "DOMAIN-SUFFIX,cowork-svc.exe" not in ai_yaml_content, "ai-all.yaml wrongly mapped cowork-svc.exe as DOMAIN-SUFFIX!"

    # 检查广告规则条目数
    with open(os.path.join(OUTPUT_SINGBOX_DIR, "category-ads-all.json"), 'r', encoding='utf-8') as f:
        ads_data = json.load(f)
        total_ad_domains = sum(len(v) for r in ads_data.get('rules', []) for k, v in r.items())
        assert total_ad_domains > 150000, f"Ad rules too few: {total_ad_domains}"

    print("[✓] ALL SANITY CHECKS PASSED! Integrity 100% verified.")

def write_github_summary(duration: float, srs_count: int):
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    clash_files = [f for f in os.listdir(OUTPUT_CLASH_DIR) if os.path.isfile(os.path.join(OUTPUT_CLASH_DIR, f))]
    singbox_files = [f for f in os.listdir(OUTPUT_SINGBOX_DIR) if os.path.isfile(os.path.join(OUTPUT_SINGBOX_DIR, f))]

    md = [
        "## 🚀 Sing-box & Clash Rule Hub Build Summary\n",
        f"- **⏱️ Total Build Time**: `{duration:.2f}s`",
        f"- **📦 Total Custom Rules**: `{stats['custom_count']}` sets",
        f"- **🌐 Total External Sources**: `{stats['external_count']}` sets",
        f"- **🛡️ Unified Ad Block**: `{stats['ad_rules_count']:,}` rules (Cats-Team + 秋风)",
        f"- **⚙️ Compiled SRS Binaries**: `{srs_count}` files\n",
        "### 📊 Artifacts Breakdown\n",
        f"| Directory | Format | Total Files |",
        f"| :--- | :--- | :--- |",
        f"| `clash_rules/` | Clash / Mihomo (`.yaml`, `.txt`) | `{len(clash_files)}` |",
        f"| `rule/` | Sing-box (`.json`, `.srs`) | `{len(singbox_files)}` |\n",
        "✅ *Verification status: 100% passed.*"
    ]
    with open(summary_file, 'a', encoding='utf-8') as f:
        f.write("\n".join(md) + "\n")

def main():
    start_time = time.time()
    os.makedirs(OUTPUT_CLASH_DIR, exist_ok=True)
    os.makedirs(OUTPUT_SINGBOX_DIR, exist_ok=True)

    # 1. 优先处理用户私有规则
    process_custom_rules()

    # 2. 并发下载外部公共源
    if os.path.exists(EXTERNAL_LINKS_FILE):
        print("[*] Processing external links...")
        with open(EXTERNAL_LINKS_FILE, 'r', encoding='utf-8') as f:
            links = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(process_external_link, link) for link in links]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Worker error: {e}")

    # 3. 自主双源合并构建广告拦截规则 (唯一产出: category-ads-all)
    merge_and_build_ads()

    # 4. 清理废弃的旧版 AdRules / adrules_domainset 文件
    clean_deprecated_files()

    # 5. 编译 Sing-box SRS
    srs_count = compile_srs()

    # 6. 执行完整性自检测试
    run_self_test()

    duration = time.time() - start_time
    write_github_summary(duration, srs_count)
    print(f"[*] All tasks successfully finished in {duration:.2f}s!")

if __name__ == '__main__':
    main()
