"""
VPN Gate SSTP 节点抓取 + 检测 + 产物发布
"""

import asyncio
import csv
import io
import json
import logging
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

try:
    import aiohttp
except ImportError:
    aiohttp = None

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vpngate")

VPNGATE_API_URLS = [
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/vpngate.csv",
]

DEFAULT_CHECK_WORKER = "https://ccs.mpsxx.cc.cd/check?sstp=vpn:vpn@"
DEFAULT_CONCURRENCY = 32
DEFAULT_TIMEOUT = 90
DEFAULT_MODE = "auto"  # auto 优先 Worker，失败或被限流时平滑回退到 TCP 直检
DEFAULT_PROBE_TIMEOUT = 6

PUBLIC_DIR = os.environ.get("PUBLIC_DIR", "public")
TEMPLATE_HTML = os.environ.get("TEMPLATE_HTML", "web/index.html")

COUNTRY_ZH = {
    "Japan": "日本",
    "United States": "美国",
    "Korea Republic of": "韩国",
    "Taiwan": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "United Kingdom": "英国",
    "Germany": "德国",
    "France": "法国",
    "Canada": "加拿大",
    "Australia": "澳大利亚",
    "Russian Federation": "俄罗斯",
    "Thailand": "泰国",
    "Vietnam": "越南",
    "India": "印度",
    "Malaysia": "马来西亚",
    "Indonesia": "印尼",
    "Philippines": "菲律宾",
    "Brazil": "巴西",
    "Netherlands": "荷兰",
    "Ukraine": "乌克兰",
    "Poland": "波兰",
    "Turkey": "土耳其",
}

EDGE_HOSTS = [
    "162.159.130.234:443",
    "162.159.133.242:443",
    "162.159.134.150:443",
    "162.159.135.158:443",
    "162.159.136.195:443",
    "162.159.137.98:443",
    "162.159.138.106:443",
    "162.159.141.14:443",
    "162.159.142.18:443",
    "162.159.143.19:443",
]


def _parse_endpoint(text):
    s = (text or "").strip()
    if not s:
        raise ValueError("端点不能为空")
    if ":" not in s:
        raise ValueError(f"端点格式非法: {s}")
    host, port_str = s.rsplit(":", 1)
    return host, int(port_str)


def check_one_local(node, timeout=DEFAULT_PROBE_TIMEOUT):
    host = node["host"]
    port = int(node["port"])
    ip = node.get("ip") or host
    t0 = time.perf_counter()
    res = {
        "host": host,
        "port": port,
        "country": node.get("country", ""),
        "country_code": node.get("country_code", ""),
        "residential": "residential" if ("vpn" in host.lower() and not host.lower().startswith("public-vpn")) else "datacenter",
        "latency_ms": None,
        "success": False,
        "verification": "tcp-only",
        "error": None,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    # 优先连接 IP，避免 DNS 解析阻断
    target = ip if ip else host
    try:
        with socket.create_connection((target, port), timeout=timeout):
            pass
        res["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        res["success"] = True
        log.info(f"[TCP] {host}:{port} OK ({res['latency_ms']}ms)")
    except Exception as e:
        res["error"] = str(e)
    return res


async def check_one_worker_aiohttp(session, node, worker_url, timeout=DEFAULT_TIMEOUT):
    host = node["host"]
    port = node["port"]
    target = f"{host}:{port}"
    encoded = urllib.parse.quote(target, safe="")
    full_url = f"{worker_url}{encoded}"

    res = {
        "host": host,
        "port": port,
        "country": node.get("country", ""),
        "country_code": node.get("country_code", ""),
        "residential": "unknown",
        "latency_ms": None,
        "success": False,
        "verification": "sstp-worker",
        "error": None,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    t0 = time.perf_counter()
    try:
        async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            text = await resp.text()

            if resp.status != 200:
                res["error"] = f"HTTP {resp.status}"
                return res

            try:
                data = json.loads(text)
            except Exception:
                res["error"] = "非JSON响应"
                return res

            res["success"] = data.get("success", False)
            res["latency_ms"] = data.get("responseTime") or elapsed_ms
            res["residential"] = "residential" if data.get("is_residential") else "datacenter"

            if res["success"]:
                log.info(f"[Worker] {host}:{port} OK ({res['latency_ms']}ms)")
            else:
                res["error"] = data.get("error") or data.get("message") or "Worker失败"
            return res

    except Exception as e:
        res["error"] = str(e)
        return res


async def check_all_worker_aiohttp(nodes, worker_url, concurrency=DEFAULT_CONCURRENCY, timeout=DEFAULT_TIMEOUT):
    conn = aiohttp.TCPConnector(limit=concurrency * 2, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=conn) as session:
        sem = asyncio.Semaphore(concurrency)

        async def worker(node):
            async with sem:
                return await check_one_worker_aiohttp(session, node, worker_url, timeout)

        tasks = [asyncio.create_task(worker(n)) for n in nodes]
        results = []
        for f in asyncio.as_completed(tasks):
            r = await f
            results.append(r)
        return results


def build_outputs(results, raw_count, sstp_count, source_name):
    passed = [r for r in results if r.get("success")]
    failed = len(results) - len(passed)

    countries = defaultdict(lambda: {"code": "", "nodes": [], "count": 0, "residential": 0, "datacenter": 0})
    for r in passed:
        c = countries[r["country"]]
        c["code"] = r["country_code"]
        c["nodes"].append(r)
        c["count"] += 1
        if r["residential"] == "residential":
            c["residential"] += 1
        else:
            c["datacenter"] += 1

    for c in countries.values():
        c["nodes"].sort(key=lambda x: (x["latency_ms"] if x["latency_ms"] is not None else 99999))

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source_name,
        "stats": {
            "raw_nodes": raw_count,
            "sstp_nodes": sstp_count,
            "checked": len(results),
            "success": len(passed),
            "failed": failed,
            "countries": len(countries),
            "residential_est": sum(c["residential"] for c in countries.values()),
            "datacenter_est": sum(c["datacenter"] for c in countries.values()),
        },
        "countries": dict(countries),
        "available": passed,
    }


def build_nodes_text(data, edge_hosts):
    countries = data.get("countries") or {}
    edge = [e.strip() for e in (edge_hosts or []) if e and e.strip()]
    if not edge:
        edge = ["162.159.130.234:443"]

    lines = []
    idx = 0
    for country_en, group in sorted(countries.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        zh = COUNTRY_ZH.get(country_en, country_en)
        for i, n in enumerate(group["nodes"], 1):
            entry = edge[idx % len(edge)]
            idx += 1
            typ = "住宅" if n["residential"] == "residential" else "机房"
            host = n["host"]
            port = n["port"]
            lines.append(f"{entry}#{zh}-{typ}-{i:02d}$sstp://vpn:vpn@{host}:{port}")

    if not lines:
        raise ValueError("无可用节点，不生成 nodes.txt")
    return "\n".join(lines) + "\n"


def build_sstp_text(data):
    endpoints = [f"{n['host']}:{n['port']}" for n in (data.get("available") or [])]
    return "\n".join(endpoints) + "\n"


def write_outputs(data, edge_hosts, public_dir=PUBLIC_DIR, template_html=TEMPLATE_HTML):
    nodes_txt = build_nodes_text(data, edge_hosts)
    sstp_txt = build_sstp_text(data)

    os.makedirs(public_dir, exist_ok=True)
    paths = []

    p_data = os.path.join(public_dir, "data.json")
    with open(p_data, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    paths.append(p_data)

    p_nodes = os.path.join(public_dir, "nodes.txt")
    with open(p_nodes, "w", encoding="utf-8") as f:
        f.write(nodes_txt)
    paths.append(p_nodes)

    p_sstp = os.path.join(public_dir, "sstp.txt")
    with open(p_sstp, "w", encoding="utf-8") as f:
        f.write(sstp_txt)
    paths.append(p_sstp)

    p_html = os.path.join(public_dir, "index.html")
    if os.path.isfile(template_html):
        with open(template_html, "r", encoding="utf-8") as f_in, open(p_html, "w", encoding="utf-8") as f_out:
            f_out.write(f_in.read())
        paths.append(p_html)

    return paths


def validate_public_dir(public_dir=PUBLIC_DIR):
    p_data = os.path.join(public_dir, "data.json")
    p_nodes = os.path.join(public_dir, "nodes.txt")
    p_sstp = os.path.join(public_dir, "sstp.txt")

    for path in (p_data, p_nodes, p_sstp):
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            raise ValueError(f"发布产物缺失或为空: {path}")

    with open(p_data, "r", encoding="utf-8") as f:
        data = json.load(f)
    return len(data.get("available") or [])


def fetch_vpngate_csv():
    headers = {"User-Agent": "Mozilla/5.0"}
    for url in VPNGATE_API_URLS:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                if "HostName" in text:
                    log.info(f"成功从 {url} 获取数据")
                    return text, url
        except Exception as e:
            log.warning(f"从 {url} 获取失败: {e}")
    raise RuntimeError("所有数据源均不可用")


def parse_vpngate_csv(csv_text):
    lines = csv_text.strip().splitlines()
    data_lines = [l for l in lines if not l.startswith("*") and l.strip()]
    if not data_lines:
        return [], 0, 0

    reader = csv.reader(io.StringIO("\n".join(data_lines)))
    header = [h.strip().lstrip("#") for h in next(reader)]
    rows = []
    for row in reader:
        if len(row) >= len(header):
            rows.append(dict(zip(header, row)))

    raw_count = len(rows)
    seen = set()
    nodes = []
    for r in rows:
        host = r.get("HostName") or r.get("IP")
        if not host:
            continue
        # 补齐完整域名后缀
        if not host.endswith(".opengw.net") and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            host = f"{host}.opengw.net"

        port_str = r.get("Port") or "443"
        try:
            port = int(port_str)
        except ValueError:
            continue

        key = (host, port)
        if key in seen:
            continue
        seen.add(key)

        nodes.append({
            "host": host,
            "ip": r.get("IP"),
            "port": port,
            "country": r.get("CountryLong", "Unknown"),
            "country_code": r.get("CountryShort", "??"),
        })

    return nodes, raw_count, len(nodes)


def main():
    mode = os.environ.get("CHECK_MODE", DEFAULT_MODE)
    worker_url = os.environ.get("CHECK_WORKER", DEFAULT_CHECK_WORKER)

    try:
        csv_text, src = fetch_vpngate_csv()
        nodes, raw_count, sstp_count = parse_vpngate_csv(csv_text)
        log.info(f"解析到 {raw_count} 个原始节点，去重后 {sstp_count} 个待测节点")
    except Exception as e:
        log.error(f"数据源获取失败: {e}")
        sys.exit(1)

    concurrency = int(os.environ.get("CHECK_CONCURRENCY", DEFAULT_CONCURRENCY))
    timeout = int(os.environ.get("CHECK_TIMEOUT", DEFAULT_TIMEOUT))

    results = []
    # 如果配置了 worker 且 aiohttp 可用，先尝试 worker 检测
    if mode in ("worker", "auto") and worker_url and aiohttp is not None:
        log.info(f"开始使用 Worker ({worker_url}) 并发检测...")
        results = asyncio.run(check_all_worker_aiohttp(nodes, worker_url, concurrency, timeout))

    passed_count = sum(1 for r in results if r.get("success"))
    # 如果 Worker 0 通过（比如遭遇外部 429 限流），自动降级为 TCP 直连检测，保证永远不会空手而归
    if passed_count == 0:
        log.warning("Worker 未检测到可用节点（可能是外部 IP 查询接口被限流），正在使用快速 TCP 连通性检测作为保底...")
        results = [check_one_local(n) for n in nodes]

    data = build_outputs(results, raw_count, sstp_count, src)
    if data["stats"]["success"] == 0:
        log.error("所有节点探测均失败，停止发布")
        sys.exit(1)

    write_outputs(data, EDGE_HOSTS, PUBLIC_DIR, TEMPLATE_HTML)
    count = validate_public_dir(PUBLIC_DIR)
    log.info(f"成功发布 {count} 个经过验证的可用节点！")


if __name__ == "__main__":
    main()
