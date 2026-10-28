#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (精简版)
=====================================
流程:
  1. 获取 VPN Gate 原始节点
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发调用检测 Worker
  5. 获取并合并优选域名与优选 API (Cloudflare 入口)
  6. 生成 public/data.json + public/index.html + public/nodes.txt
"""

import base64
import csv
import io
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://你的域名/check?sstp=vpn:vpn@").strip()
# 规范化: 允许只传 https://xxx/check, 自动补上 Worker 期望的查询串前缀
if WORKER_CHECK_URL and "?" not in WORKER_CHECK_URL:
    WORKER_CHECK_URL = WORKER_CHECK_URL.rstrip("/") + "?sstp=vpn:vpn@"

CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
CHECK_MODE = os.environ.get("CHECK_MODE", "auto").strip().lower()
NODES_FORMAT = os.environ.get("NODES_FORMAT", "ip").strip().lower()
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "8"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# 静态优选域名池
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "saas.sin.fan:443,cdn.204910.best:443,www.mfyx.cn:443,p.etime.vip:443,cdn.ctn32.us.kg:443,cf.877774.xyz:443,spring.io:443,"
        "cf.nyanya.moe:443,www.sloomb.com:443,op.chinwa.eu.cc:443,www.leics.police.uk:443,securecircle.com:443,www.shopify.com:443,"
        "www.carousell.sg:443,www.dbs.com.sg:443,openai.com:443,linear.app:443,www.bilibili.com:443,uspto.gov:443,www.vmware.com:443",
    ).split(",")
    if h.strip()
]

# 优选 API 地址配置 (支持逗号分隔多个，可配置在 GitHub Action Secret / Env 中)
OPTIMAL_API = os.environ.get("OPTIMAL_API", "https://cf.090227.xyz/ct?ips=6&port=443")

NODES_URL = os.environ.get("NODES_URL", "https://miaopasixx.github.io/gate/nodes.txt")

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None

def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败")

def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
        "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1),
    }

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7: continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows

def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows

# ---------------------------------------------------------------------------
# 优选 API 获取与解析
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    """
    拉取优选 API，解析如: 172.66.1.179:443#CF 电信优选 格式的内容
    提取出纯 'IP:端口' (例如 172.66.1.179:443)
    """
    if not api_urls_str.strip():
        return []
    
    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                lines = resp.text.strip().splitlines()
                count = 0
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # 剥离 # 后的备注，提取 IP:端口
                    endpoint = line.split("#")[0].strip()
                    if endpoint:
                        # 补充缺失端口默认 443
                        if ":" not in endpoint:
                            endpoint = f"{endpoint}:443"
                        endpoints.append(endpoint)
                        count += 1
                log("OPTIMAL API", f"成功从 API 获取到 {count} 个优选端点")
            else:
                log("OPTIMAL API", f"API 返回状态码异常: {resp.status_code}")
        except Exception as e:
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {e}")
    return endpoints

def get_combined_edge_hosts():
    """
    合并静态优选域名与优选 API 端点
    """
    # 1. 优先读取 HOSTS_ENTRY 或 EDGE_HOSTS
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS

    # 2. 拉取优选 API 端点
    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)

    # 3. 合并与去重 (保留原始列表顺序)
    combined = []
    seen = set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)

    log("EDGE POOL", f"汇总入口地址池: 静态域名 {len(static_hosts)} 个, API 获取 {len(api_hosts)} 个, 合并有效入口共 {len(combined)} 个")
    return combined if combined else EDGE_HOSTS

# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg): continue
        m = _REMOTE_RE.search(cfg)
        if not m: continue
        port = int(m.group(1))
        if not (1 <= port <= 65535): continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({"host": host, "port": port, "ip": r["ip"], "country": r["country_long"], "country_code": r["country_short"]})
    return nodes

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen: continue
        seen.add(key)
        out.append(n)
    return out

# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True: return "datacenter"
    if is_datacenter is False: return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS): return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS): return "residential"
    h = host.lower()
    if h.startswith("public-vpn"): return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h): return "residential"
    return "unknown"

def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        try:
            j = r.json()
        except ValueError:
            out["error"] = f"非JSON响应(可能是WAF/错误页): {r.text[:200]}"
            out["worker_error"] = True
            return out
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out

def check_one_local(node):
    """本地 TCP 直连探测: 连上 443 即认为 SSTP 枢纽存活"""
    host = node["host"]
    port = int(node["port"])
    tmo = min(float(PROBE_TIMEOUT), float(CHECK_TIMEOUT))
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{host}:{port}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    out["probe"] = "tcp"
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=tmo):
            lat = int((time.time() - t0) * 1000)
            out["success"] = True
            out["status"] = "success"
            out["latency_ms"] = lat
            out["error"] = None
            try:
                out["residential"] = classify_network(host, None, None)
            except Exception:
                pass
    except socket.timeout:
        out["success"] = False
        out["error"] = f"TCP超时({tmo:.0f}s)"
    except OSError as exc:
        out["success"] = False
        out["error"] = f"OSError: {exc}"
    except Exception as exc:
        out["success"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _run_worker(nodes, session):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as exc:
                log("WARN", f"检测任务异常: {type(exc).__name__}: {exc}")
    return results


def _run_local(nodes):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one_local, n) for n in nodes]
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as exc:
                log("WARN", f"本地探测异常: {type(exc).__name__}: {exc}")
    return results


def check_all(nodes, session):
    """
    检测分发
      CHECK_MODE=worker : 只走 Cloudflare Worker (fetch 探测, 对 SSTP 天然不可靠)
      CHECK_MODE=local  : 只走本地 TCP 直连 (runner 有完整网络栈, 推荐)
      CHECK_MODE=auto   : 先 Worker, 全失败自动降级 local (默认)
    """
    mode = CHECK_MODE if CHECK_MODE in ("worker", "local", "auto") else "auto"

    if mode == "local" or not WORKER_CHECK_URL:
        if not WORKER_CHECK_URL and mode != "local":
            log("CHECK", "CHECK_WORKER 为空, 自动切换本地 TCP 直连")
        log("CHECK", f"检测模式: 本地 TCP 直连 (并发 {CONCURRENCY}, 单次超时 {min(PROBE_TIMEOUT, CHECK_TIMEOUT):.0f}s)")
        return _run_local(nodes)

    if mode == "worker":
        log("CHECK", f"检测模式: Cloudflare Worker (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT:.0f}s)")
        return _run_worker(nodes, session)

    # auto
    log("CHECK", f"检测模式: auto — 先 Worker, 全失败再本地直连")
    res = _run_worker(nodes, session)
    ok = [r for r in res if r.get("success")]
    werr = [r for r in res if not r.get("success") and r.get("worker_error")]
    if res and not ok and len(werr) == len(res):
        log("WARN", f"Worker 判定全部失败 ({len(werr)}/{len(res)}), 自动切换本地 TCP 直连重测")
        return _run_local(nodes)
    return res

# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data

_EDGE_IP_CACHE = {}


def resolve_edge_entry(entry):
    """把 '域名:443' 解析成 'IP:443'，解析失败原样返回"""
    if not entry:
        return entry
    host, port = entry, "443"
    if ":" in entry:
        head, tail = entry.rsplit(":", 1)
        if tail.isdigit():
            host, port = head, tail
    if host in _EDGE_IP_CACHE:
        ip = _EDGE_IP_CACHE[host]
    else:
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = host
        _EDGE_IP_CACHE[host] = ip
    return f"{ip}:{port}"


def build_nodes_text(data, edge_hosts):
    """
    生成 edgetunnel「自定义优选IP」可用的列表。

    NODES_FORMAT:
      ip     (默认) 每行 = IP:端口#备注         <- 推荐, 避开 SNI 不匹配
      host          每行 = 域名:端口#备注       <- 用原始域名
      tunnel        每行 = 地址:端口#备注$sstp://vpn:vpn@host:port  <- 旧格式

    注意: 优选入口只负责"替换 server 的 IP 层"，
    servername / Host 必须保持你自己的 Worker 域名，否则 CF 边缘不会路由到你的 Worker。
    """
    fmt = NODES_FORMAT if NODES_FORMAT in ("ip", "host", "tunnel") else "ip"

    countries = data.get("countries") or {}
    edge = [e for e in (edge_hosts or []) if e] or list(EDGE_HOSTS) or ["1.1.1.1:443"]
    if fmt == "ip":
        edge = [resolve_edge_entry(e) for e in edge]

    lines = []
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            tail = f"$sstp://vpn:vpn@{n['host']}:{n['port']}" if fmt == "tunnel" else ""
            lines.append(f"{entry}#{zh}-住宅-{i:02d}{tail}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            tail = f"$sstp://vpn:vpn@{n['host']}:{n['port']}" if fmt == "tunnel" else ""
            lines.append(f"{entry}#{zh}-机房-{i:02d}{tail}")

    # 兜底: 无可用节点时输出纯优选入口, 保证 nodes.txt 非空
    if not lines:
        for i, entry in enumerate(edge, 1):
            lines.append(f"{entry}#优选-{i:02d}")
        log("NODES", f"[兜底] 无可用节点, nodes.txt 输出 {len(lines)} 条优选入口")

    return "\n".join(lines) + "\n"


def write_outputs(data, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = (
            "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
            "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
            "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>"
        )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_text = build_nodes_text(data, edge_hosts)
    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(nodes_text)

    # 产物自检: 大小 + 行数 + 前 3 行, 直接打日志, 不用等部署完再猜
    node_lines = nodes_text.splitlines()
    try:
        size = os.path.getsize(nodes_path)
        log("NODES", f"nodes.txt: {size} bytes, {len(node_lines)} 行")
        for ln in node_lines[:3]:
            log("NODES", f"  {ln}")
    except Exception:
        pass

    # 纯 SSTP 节点列表: 给 SSTP 客户端用, 与 Cloudflare 完全无关
    sstp_lines = [f"{n['host']}:{n['port']}" for n in (data.get("available") or [])]
    sstp_path = os.path.join(PUBLIC_DIR, "sstp.txt")
    with open(sstp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sstp_lines) + ("\n" if sstp_lines else ""))
    log("NODES", f"sstp.txt: {len(sstp_lines)} 个 SSTP 节点 (与 Cloudflare 无关)")

    for p in (data_path, html_path, nodes_path):
        if not os.path.exists(p):
            log("WARN", f"产物未生成: {p}")
        elif os.path.getsize(p) == 0:
            log("WARN", f"产物为空: {p}")

    return data_path, html_path, nodes_path

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)}")
    if WORKER_CHECK_URL:
        log("CLOUDFLARE WORKER", f"Worker 地址: {WORKER_CHECK_URL}<host>:<port>")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    if worker_errors:
        log("CLOUDFLARE WORKER", f"检测失败: {len(failed)} (其中 Worker 异常 {len(worker_errors)})")
    else:
        log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}")
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    # Worker 异常分类统计 —— 之前 N 个异常全糊成一行, 看不到具体原因
    if worker_errors:
        buckets = {}
        for r in worker_errors:
            key = str(r.get("error") or "unknown")
            if ":" in key:
                key = key.split(":")[0][:60]
            buckets[key] = buckets.get(key, 0) + 1
        log("WORKER DIAG", f"Worker 异常分类 ({len(worker_errors)} 条):")
        for k, v in sorted(buckets.items(), key=lambda kv: -kv[1]):
            log("WORKER DIAG", f"  {v:>4d}  x  {k}")
        s0 = worker_errors[0]
        log("WORKER DIAG", f"样本错误: {s0.get('error')}")
        try:
            probe = WORKER_CHECK_URL + quote(f"{s0['host']}:{s0['port']}", safe="")
            log("WORKER DIAG", f"实际请求地址: {probe}")
        except Exception:
            pass

    # ==== 核心改动: 检测全挂不再中断流程 ====
    # 原逻辑在这里 die(), 导致下面的 write_outputs() 永远不执行,
    # public/ 为空 -> Pages 上传空目录 -> nodes.txt 404。
    # nodes.txt 的数据源是优选域名, 跟 SSTP 检测结果无关, 不该被连累。
    degraded = False
    if uniq and not success and len(worker_errors) == len(uniq):
        degraded = True
        log("WARN", "Worker 全部请求异常 — 检测服务不可用")
        log("WARN", "降级运行: 页面无可用节点, 但 nodes.txt / index.html 仍会正常生成")

    try:
        data = build_outputs(results, raw_count, sstp_count, source)
    except Exception as exc:
        log("WARN", f"build_outputs 异常: {type(exc).__name__}: {exc}")
        log("WARN", "使用最小数据集继续, 保证产物不丢失")
        data = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "source": source,
            "worker": WORKER_CHECK_URL,
            "stats": {
                "raw_nodes": raw_count,
                "sstp_nodes": sstp_count,
                "checked": len(results),
                "success": 0,
                "failed": len(results),
                "countries": 0,
                "residential_est": 0,
                "datacenter_est": 0,
            },
            "countries": {},
            "available": [],
        }

    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data.get('stats', {}).get('countries', 0)}")

    # 动态拉取 API 并与静态优选域名混合
    edge_hosts = get_combined_edge_hosts() or list(EDGE_HOSTS)
    if not edge_hosts:
        log("WARN", "优选域名池为空, nodes.txt 将使用兜底格式")

    data_path, html_path, nodes_path = write_outputs(data, edge_hosts)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (一次配置, 之后自动更新)")
    if degraded:
        log("WARN", "本次为降级运行: 页面无可用节点, 但 nodes.txt 已正常产出")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
