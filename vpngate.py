"""
VPN Gate SSTP 节点抓取 + Cloudflare Worker 检测 + 产物发布
"""

import asyncio
import csv
import io
import ipaddress
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

DEFAULT_CHECK_WORKER = "https://ccf.mpsxx.cc.cd/check?sstp=vpn:vpn@"
DEFAULT_CONCURRENCY = 32
DEFAULT_TIMEOUT = 90
DEFAULT_MODE = "worker"
DEFAULT_PROBE_TIMEOUT = 8

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


def _parse_endpoint(text, *, edge=False):
    s = (text or "").strip()
    if not s:
        raise ValueError("端点不能为空")
    if any(ch in s for ch in (" ", "\t", "\r", "\n")):
        raise ValueError(f"端点包含空白字符: {s!r}")
    if any(token in s for token in ("$", "#", "://", "/")):
        raise ValueError(f"端点包含非法分隔符或路径: {s!r}")
    if "@" in s:
        raise ValueError(f"端点不能包含认证信息: {s!r}")

    host = ""
    port_str = ""
    if s.startswith("["):
        idx = s.find("]")
        if idx == -1 or not s[idx:].startswith(":"):
            raise ValueError(f"端点必须是 host:port 或 [IPv6]:port: {s!r}")
        host = s[1:idx]
        port_str = s[idx + 2 :]
    else:
        parts = s.split(":")
        if len(parts) != 2:
            raise ValueError(f"端点必须是 host:port 或 [IPv6]:port: {s!r}")
        host, port_str = parts

    if not host or not port_str.isdigit():
        raise ValueError(f"端点端口无效: {s!r}")
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ValueError(f"端口超出合法范围 (1-65535): {port}")

    if not edge and host.startswith("["):
        raise ValueError(f"目标主机格式非法: {host!r}")
    return host, port


def _node_endpoint(node):
    host = str(node.get("host") or "").strip()
    port = int(node.get("port") or 0)
    _parse_endpoint(f"{host}:{port}")
    return f"{host}:{port}"


def is_publishable_result(result):
    return bool(result.get("success")) and result.get("verification") == "sstp-worker"


def check_one_local(node, timeout=DEFAULT_PROBE_TIMEOUT):
    host = node["host"]
    port = int(node["port"])
    t0 = time.perf_counter()
    res = {
        "host": host,
        "port": port,
        "country": node.get("country", ""),
        "country_code": node.get("country_code", ""),
        "residential": "unknown",
        "latency_ms": None,
        "success": False,
        "verification": "tcp-only",
        "tcp_reachable": False,
        "error": None,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        res["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        res["tcp_reachable"] = True
        log.debug(f"[TCP] {host}:{port} OK ({res['latency_ms']}ms)")
    except Exception as e:
        res["error"] = f"tcp: {e}"
        log.debug(f"[TCP] {host}:{port} FAIL: {e}")
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
        "exit": None,
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
                res["error"] = "非JSON响应(可能是WAF/错误页)"
                return res

            if not isinstance(data.get("success"), bool):
                res["error"] = "响应缺少布尔类型 success 字段"
                return res

            res["success"] = data.get("success", False)
            res["latency_ms"] = data.get("latency") or data.get("latency_ms") or elapsed_ms

            loc = data.get("location") or {}
            if loc:
                res["exit"] = {
                    "ip": loc.get("query") or loc.get("ip"),
                    "country": loc.get("country"),
                    "org": loc.get("org") or loc.get("isp"),
                }
            res["residential"] = "residential" if data.get("is_residential") else "datacenter"

            if res["success"]:
                log.info(f"[Worker] {host}:{port} OK ({res['latency_ms']}ms, {res['residential']})")
            else:
                res["error"] = data.get("message") or data.get("error") or "Worker判定不可用"
                log.debug(f"[Worker] {host}:{port} FAIL: {res['error']}")
            return res

    except asyncio.TimeoutError:
        res["error"] = f"超时(>{timeout}s)"
        return res
    except Exception as e:
        res["error"] = f"异常: {type(e).__name__}: {e}"
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
    passed = [r for r in results if is_publishable_result(r)]
    failed = len(results) - len(passed)

    countries = defaultdict(lambda: {"code": "", "nodes": [], "count": 0, "residential": 0, "datacenter": 0})
    for r in passed:
        c = countries[r["country"]]
        c["code"] = r["country_code"]
        c["nodes"].append(r)
        c["count"] += 1
        if r["residential"] == "residential":
            c["residential"] += 1
        elif r["residential"] == "datacenter":
            c["datacenter"] += 1

    for c in countries.values():
        c["nodes"].sort(
            key=lambda x: (
                0 if x["residential"] == "residential" else 1,
                x["latency_ms"] if x["latency_ms"] is not None else 99999,
            )
        )

    res_est = sum(c["residential"] for c in countries.values())
    dc_est = sum(c["datacenter"] for c in countries.values())

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source_name,
        "worker": os.environ.get("CHECK_WORKER", DEFAULT_CHECK_WORKER),
        "stats": {
            "raw_nodes": raw_count,
            "sstp_nodes": sstp_count,
            "checked": len(results),
            "success": len(passed),
            "failed": failed,
            "countries": len(countries),
            "residential_est": res_est,
            "datacenter_est": dc_est,
        },
        "countries": dict(countries),
        "available": passed,
    }


def build_nodes_text(data, edge_hosts):
    countries = data.get("countries") or {}
    edge = [e.strip() for e in (edge_hosts or []) if e and e.strip()]
    if not edge:
        raise ValueError("Cloudflare 入口池为空，无法生成 nodes.txt")
    for entry in edge:
        _parse_endpoint(entry, edge=True)

    sorted_countries = sorted(countries.items(), key=lambda kv: (-kv[1]["count"], kv[0]))

    lines = []
    idx = 0
    for country_en, group in sorted_countries:
        zh = COUNTRY_ZH.get(country_en, country_en)
        res_nodes = [n for n in group["nodes"] if n["residential"] == "residential"]
        dc_nodes = [n for n in group["nodes"] if n["residential"] != "residential"]

        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{_node_endpoint(n)}")

        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{_node_endpoint(n)}")

    if not lines:
        raise ValueError("没有经 SSTP Worker 验证成功的节点，不生成 nodes.txt")
    return "\n".join(lines) + "\n"


def build_sstp_text(data):
    endpoints = [_node_endpoint(n) for n in (data.get("available") or [])]
    if not endpoints:
        raise ValueError("没有经 SSTP Worker 验证成功的节点，不生成 sstp.txt")
    return "\n".join(endpoints) + "\n"


def validate_publish_bundle(data, nodes_text, sstp_text):
    available = data.get("available") or []
    if not available:
        raise ValueError("发布数据中无可用节点")

    for node in available:
        if not is_publishable_result(node):
            raise ValueError(f"包含未经 SSTP Worker 成功验证的节点: {node}")

    expected_endpoints = [_node_endpoint(n) for n in available]
    if len(expected_endpoints) != len(set(expected_endpoints)):
        raise ValueError("发布数据中存在重复的真实端点")

    node_lines = [line.strip() for line in (nodes_text or "").splitlines() if line.strip()]
    if not node_lines:
        raise ValueError("nodes.txt 为空")

    extracted_endpoints = []
    for line in node_lines:
        match = re.fullmatch(r"^([^#$]+)#([^$]+)\$sstp://vpn:vpn@([^#$]+)$", line)
        if not match:
            raise ValueError(
                f"nodes.txt 格式不合规（必须是完整链式代理 entry#tag$sstp://vpn:vpn@host:port）: {line}"
            )
        entry, tag, target = match.groups()
        _parse_endpoint(entry, edge=True)
        if not tag.strip():
            raise ValueError(f"nodes.txt 标签不能为空: {line}")
        host, port = _parse_endpoint(target)
        extracted_endpoints.append(f"{host}:{port}")

    if extracted_endpoints != expected_endpoints:
        raise ValueError("nodes.txt 的目标端点列表与 data.available 不一致")

    sstp_lines = [line.strip() for line in (sstp_text or "").splitlines() if line.strip()]
    for line in sstp_lines:
        _parse_endpoint(line)

    if sstp_lines != expected_endpoints:
        raise ValueError("sstp.txt 与 data.available 端点列表不一致")

    stats = data.get("stats") or {}
    if stats.get("success") != len(available):
        raise ValueError("data.stats.success 与 data.available 长度不匹配")


def write_outputs(data, edge_hosts, public_dir=PUBLIC_DIR, template_html=TEMPLATE_HTML):
    nodes_txt = build_nodes_text(data, edge_hosts)
    sstp_txt = build_sstp_text(data)
    validate_publish_bundle(data, nodes_txt, sstp_txt)

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
    else:
        log.warning(f"模板文件 {template_html} 不存在，跳过生成 index.html")

    return paths


def validate_public_dir(public_dir=PUBLIC_DIR):
    p_data = os.path.join(public_dir, "data.json")
    p_nodes = os.path.join(public_dir, "nodes.txt")
    p_sstp = os.path.join(public_dir, "sstp.txt")
    p_html = os.path.join(public_dir, "index.html")

    for path in (p_data, p_nodes, p_sstp, p_html):
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            raise ValueError(f"发布产物缺失或为空: {path}")

    with open(p_data, "r", encoding="utf-8") as f:
        data = json.load(f)
    with open(p_nodes, "r", encoding="utf-8") as f:
        nodes_txt = f.read()
    with open(p_sstp, "r", encoding="utf-8") as f:
        sstp_txt = f.read()

    validate_publish_bundle(data, nodes_txt, sstp_txt)
    return len(data.get("available") or [])


def fetch_vpngate_csv():
    headers = {"User-Agent": "Mozilla/5.0 (compatible; VPNGateChecker/2.0)"}
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
    raise RuntimeError("所有 VPN Gate 数据源均不可用")


def parse_vpngate_csv(csv_text):
    lines = csv_text.strip().splitlines()
    data_lines = [l for l in lines if not l.startswith("*") and l.strip()]
    if not data_lines:
        return [], 0, 0

    reader = csv.reader(io.StringIO("\n".join(data_lines)))
    try:
        header = next(reader)
    except StopIteration:
        return [], 0, 0

    header = [h.strip().lstrip("#") for h in header]
    rows = []
    for row in reader:
        if len(row) >= len(header):
            rows.append(dict(zip(header, row)))

    raw_count = len(rows)
    seen = set()
    nodes = []
    for r in rows:
        host = r.get("HostName") or r.get("IP")
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
            "port": port,
            "country": r.get("CountryLong", "Unknown"),
            "country_code": r.get("CountryShort", "??"),
        })

    return nodes, raw_count, len(nodes)


def main():
    mode = os.environ.get("CHECK_MODE", DEFAULT_MODE)
    worker_url = os.environ.get("CHECK_WORKER", DEFAULT_CHECK_WORKER)
    worker_ok = os.environ.get("WORKER_OK", "true").lower() == "true"

    if mode == "worker" and (not worker_url or not worker_ok):
        log.error("生产模式配置为 worker，但检测 Worker 不可用或未通过自检；停止发布，保留现有 Pages")
        sys.exit(1)

    try:
        csv_text, src = fetch_vpngate_csv()
        nodes, raw_count, sstp_count = parse_vpngate_csv(csv_text)
        log.info(f"解析到 {raw_count} 个原始节点，去重后 {sstp_count} 个 SSTP 待测节点")
    except Exception as e:
        log.error(f"数据源获取失败: {e}")
        sys.exit(1)

    max_check = int(os.environ.get("MAX_CHECK_NODES", "0"))
    if max_check > 0:
        nodes = nodes[:max_check]

    concurrency = int(os.environ.get("CHECK_CONCURRENCY", DEFAULT_CONCURRENCY))
    timeout = int(os.environ.get("CHECK_TIMEOUT", DEFAULT_TIMEOUT))

    if mode == "worker":
        if aiohttp is None:
            log.error("缺少 aiohttp 依赖，无法运行 worker 并发检测")
            sys.exit(1)
        results = asyncio.run(check_all_worker_aiohttp(nodes, worker_url, concurrency, timeout))
    else:
        results = [check_one_local(n) for n in nodes]

    data = build_outputs(results, raw_count, sstp_count, src)
    if data["stats"]["success"] == 0:
        log.error("没有经 SSTP Worker 验证成功的节点；停止生成，保留上一次成功的 Pages 部署")
        sys.exit(1)

    write_outputs(data, EDGE_HOSTS, PUBLIC_DIR, TEMPLATE_HTML)
    count = validate_public_dir(PUBLIC_DIR)
    log.info(f"成功发布 {count} 个经过验证的 SSTP 节点")


if __name__ == "__main__":
    main()
