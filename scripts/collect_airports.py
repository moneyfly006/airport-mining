#!/usr/bin/env python3
"""机场清单聚合器 — 多源搜集 + 状态记录 + 增量对比 + 白名单优先

需求（2026-08）：
  1. 搜集所有机场列表（多个 GitHub 源，有人专门整理的）
  2. 逐个排查（SSPanel vue 版？可邮箱注册？出节点？）
  3. 不符合的排除，符合的保留并做好记录
  4. 下次优先扫描白名单机场
  5. 继续排查新增机场，与上次对比，保留新增的符合项

数据流：
  [GitHub 源] → 提取域名 → 归一化 → 与 registry 对比
      ├─ 新增域名 → 加入待排查队列
      └─ 已知白名单 → 优先扫描
  → 逐个扫描（复用 scan_sspanel_airports 的 probe/register/fetch）
  → 写回 registry（状态: pending/qualified/excluded/failed）
  → 白名单 = qualified 的机场

状态文件（进仓库，跨 CI 运行持久）：
  artifacts/airport_registry.json
    {
      "version": "...",
      "updated_at": "...",
      "sources": {源名: {fetched_at, domains}},
      "airports": {
        "heduian.my": {
          "name": "heduian",
          "base": "https://www.heduian.my",
          "sources": ["builtin"],
          "first_seen": "...",
          "last_scanned": "...",
          "status": "qualified",       # pending/qualified/excluded/failed
          "probe": true,               # SSPanel vue 版
          "registered": true,
          "node_count": 20,
          "link_count": 20,
          "note": ""
        }
      },
      "whitelist": ["heduian.my"]      # status=qualified 的域名（扫描优先）
    }

环境变量：
  AIRPORTS_REFRESH=1        强制重新抓取所有源（默认: 仅抓取未抓取过的源）
  AIRPORTS_RESET=1          清空 registry 重新开始（小心使用）
  SCAN_ONLY_PROBE=1         只探测不注册
  SCAN_AIRPORTS             追加机场 JSON（同 scan_sspanel_airports）
  COLLECT_SOURCES           逗号分隔的源名子集（默认全部）

输出：
  artifacts/airport_registry.json  状态文件
  nodes/scan_<slug>_nodes.txt      每个 qualified 机场的节点
  nodes/scan_<slug>.probe.json     探测明细
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scan_sspanel_airports as scan  # noqa: E402  复用探测/注册/拉节点
from _repo_paths import NODES_DIR  # noqa: E402

# registry 放 nodes/ 下（artifacts/ 被 gitignore，无法跨 CI 持久化增量对比）
REGISTRY_FILE = NODES_DIR / "airport_registry.json"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0"

# 多源机场清单（有人专门整理，定期更新）。值为 (repo, path, 解析函数)。
# 解析函数: (text) -> list[str] 返回域名列表
SOURCES: dict[str, dict] = {
    "builtin": {
        "domains": ["heduian.my"],
        "fetched": True,  # 内建，无需抓取
    },
    "jichang-tuijian": {
        "url": "https://raw.githubusercontent.com/jctz123/jichang-tuijian/main/README.md",
        "kind": "markdown",
    },
    "dijiajichang": {
        "url": "https://raw.githubusercontent.com/KaWaIDeSuNe/dijiajichang/main/README.md",
        "kind": "markdown",
    },
    "xingjiabijichang": {
        "url": "https://raw.githubusercontent.com/KaWaIDeSuNe/xingjiabijichang/main/README.md",
        "kind": "markdown",
    },
    "cheap-airports": {
        "url": "https://raw.githubusercontent.com/jichangtuijian-cheap/cheap-airports/main/README.md",
        "kind": "markdown",
    },
    "vpn-deep-test": {
        "url": "https://raw.githubusercontent.com/ChaselDutt/VPN-Deep-Test/main/README.md",
        "kind": "markdown",
    },
    "airport-recommendations-2026": {
        "url": "https://raw.githubusercontent.com/everett7623/airport-recommendations-2026/main/data/airports.json",
        "kind": "airports-json",
    },
    "telegram-group": {
        "url": "https://raw.githubusercontent.com/itgoyo/TelegramGroup/master/README.md",
        "kind": "markdown",
    },
    # lkmvip/sspanel-mining: 活跃续更版（每 12 小时自动采集，881 个 CSV 快照，
    # 最新 2025-11-03）。kind=sspanel-csv-latest 用 GitHub API 动态定位最新 CSV。
    "sspanel-mining": {
        "url": ("https://api.github.com/repos/lkmvip/sspanel-mining/contents/"
                "src/database/sspanel_hosts/classifier"),
        "kind": "sspanel-csv-latest",
        # 只取能邮箱注册的候选（其余分类作为参考记录，不进扫描队列）
        "include_labels": ["Normal", "Email Validation"],
        # 限制注册(邮箱) 也纳入尝试（黑名单域名可能只封部分邮箱，随机邮箱可过）
        "include_labels_ext": ["限制注册(邮箱)"],
    },
    # hwanz/SSR-V2ray-Trojan: 2026 机场推荐与评测（18k+ stars，2026-08 活跃）
    # 54 个机场区块，官网多带 /#/register?code= 邀请码链接 → 域名 + 邀请码一并入库
    "hwanz-airports": {
        "url": "https://raw.githubusercontent.com/hwanz/SSR-V2ray-Trojan/main/README.md",
        "kind": "markdown-with-code",
    },
}

# 明显非机场的域名（交易所/社交/导航/服务商）：域名中包含以下 token 即跳过
# （用 (^|\.) 前缀 + (\.|$) 边界，避免误杀 dabai.in / kuaizai.xyz / heduian.my）
_SKIP_RE = re.compile(
    r"(^|\.)(github|raw\.github|t\.me|telegram|twitter|youtube|youtu\.be|bilibili|binance|okx|"
    r"bitget|bybit|htx|mexc|wise|imgur|telegra|img\.shields|creativecommons|"
    r"nssurge|visitor-badge|laobi|komarev|star-history|opencode|ghproxy|jsdelivr|ecosyste|"
    r"w3\.org|giter|awesome|go\.uukk|cdn|githubusercontent|apache|gnu|mit|mozilla|"
    r"play\.google|teleme|tg10000|botostore|botsarchive|hackmd|volcengine|thedevs|"
    r"fastclip|hamibot|gmgn|0xnav|debot|infotelbot|meta\.appinn|racknerd|hostbrr|niceduck|"
    r"vps\.dance|geph|sms-activate|accounts|promote|shop|faka|dash|h5|"
    r"web01|web1|inv06|ivt01|a22|ftzaff|qytaff|lcgoto|go2lk|pages\.dev|"
    r"go\.chynet|go\.dginv|asus\.im)(\.|$)"
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fetch_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=25) as resp:
        return resp.read().decode("utf-8", errors="replace")


# 最近一次 sspanel-csv-latest 源实际使用的 CSV 文件名（写入 registry 便于追溯）
_LAST_CSV_NAME = ""


def fetch_latest_sspanel_csv(api_dir_url: str) -> str:
    """通过 GitHub API 列出 classifier 目录，取文件名最新的 CSV 并下载。

    文件命名 mining_<YYYY-MM-DD HH-MM-SS>.csv，按名称排序即时间序。
    """
    global _LAST_CSV_NAME
    listing = json.loads(fetch_text(api_dir_url))
    csv_names = sorted(
        f["name"] for f in listing
        if isinstance(f, dict) and f.get("name", "").endswith(".csv")
    )
    if not csv_names:
        raise RuntimeError(f"classifier 目录无 CSV: {api_dir_url}")
    latest = csv_names[-1]
    _LAST_CSV_NAME = latest
    import urllib.parse as _up

    raw_url = (
        "https://raw.githubusercontent.com/lkmvip/sspanel-mining/main/"
        f"src/database/sspanel_hosts/classifier/{_up.quote(latest)}"
    )
    print(f"  [sspanel-mining] 最新 CSV: {latest}")
    return fetch_text(raw_url)


def _clean_domain(raw: str) -> str:
    dom = raw.strip().lower().rstrip(".,;:)]}>\"'")
    # 去掉路径/query（保留域名 + 可能的端口）
    dom = dom.split("/")[0].split("?")[0]
    # 去 IDN punycode 之外的杂字符
    if not re.fullmatch(r"[a-z0-9.-]+", dom):
        return ""
    # 去掉开头的 www.（机场域名通常 www 与裸域等价）
    if dom.startswith("www."):
        dom = dom[4:]
    return dom


# 全局: 域名 -> SSPanel Mining 分类标签（供 registry 参考记录）
_SSPANEL_LABELS: dict[str, str] = {}
# 全局: 域名 -> 注册邀请码（从注册链接提取，供 registry 参考）
_INVITE_CODES: dict[str, str] = {}


def parse_markdown_domains(text: str) -> list[str]:
    found: set[str] = set()
    # markdown 链接 [x](url) 和裸 URL
    for m in re.finditer(r"https?://([^\s)\]]+)", text):
        dom = _clean_domain(m.group(1))
        if dom and not _SKIP_RE.search(dom) and "." in dom:
            found.add(dom)
    return sorted(found)


def parse_markdown_with_codes(text: str) -> list[str]:
    """markdown 链接解析 + 提取注册邀请码。

    匹配 [名称](https://域名/.../register?code=XXX) 或裸 URL；
    域名入 found，code 写入 _INVITE_CODES（供 registry 参考）。
    """
    found: set[str] = set()
    for m in re.finditer(r"https?://([^\s)\]]+)", text):
        url = m.group(0).rstrip(".,;)]}>\"'")
        um = re.match(r"https?://([^/]+)", url)
        if not um:
            continue
        dom = _clean_domain(um.group(1))
        if not dom or _SKIP_RE.search(dom) or "." not in dom:
            continue
        found.add(dom)
        code_m = re.search(r"(?:register|signup)[^?#]*[?&]code=([A-Za-z0-9_-]+)", url)
        if code_m and dom not in _INVITE_CODES:
            _INVITE_CODES[dom] = code_m.group(1)
    return sorted(found)


def parse_airports_json(text: str) -> list[str]:
    lines = [l for l in text.splitlines() if not l.strip().startswith("//")]
    data = json.loads("\n".join(lines))
    found: set[str] = set()
    for category in data.get("categories", {}).values():
        for airport in category.get("airports", []):
            for key in ("url", "website", "official", "register"):
                url = airport.get(key)
                if url:
                    m = re.match(r"https?://([^/]+)", str(url))
                    if m:
                        dom = _clean_domain(m.group(1))
                        if dom and not _SKIP_RE.search(dom):
                            found.add(dom)
    return sorted(found)


def parse_sspanel_csv(text: str, include: set[str], include_ext: set[str]) -> list[str]:
    """SSPanel Mining CSV: url,label 两列。只返回 include 分类的站点域名。

    也把 exclude 分类写进全局 _SSPANEL_LABELS 供 registry 记录。
    """
    import csv
    import io

    found: set[str] = set()
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        url = str(row.get("url", "")).strip()
        label = str(row.get("label", "")).strip()
        if not url:
            continue
        m = re.match(r"https?://([^/]+)", url)
        if not m:
            continue
        dom = _clean_domain(m.group(1))
        if not dom:
            continue
        if label in include or label in include_ext:
            found.add(dom)
        _SSPANEL_LABELS[dom] = label
    return sorted(found)


def load_registry() -> dict:
    if REGISTRY_FILE.exists():
        try:
            return json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {
        "version": 1,
        "updated_at": "",
        "sources": {},
        "airports": {},
        "whitelist": [],
    }


def save_registry(reg: dict) -> None:
    reg["updated_at"] = now()
    reg["whitelist"] = sorted(
        dom for dom, a in reg["airports"].items() if a.get("status") == "qualified"
    )
    REGISTRY_FILE.write_text(
        json.dumps(reg, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )


def collect_domains(refresh: bool) -> tuple[dict, dict]:
    """抓取所有源，返回 {源名: [域名]} 和 {源名: {fetched_at, domains}}。"""
    registry = load_registry()
    source_domains: dict[str, list[str]] = {}
    source_meta: dict[str, dict] = {}

    selected = os.getenv("COLLECT_SOURCES", "").strip()
    selected_set = set(selected.split(",")) if selected else set(SOURCES.keys())

    for name, spec in SOURCES.items():
        if name not in selected_set:
            continue
        if spec.get("fetched"):
            source_domains[name] = list(spec["domains"])
            source_meta[name] = {"fetched_at": now(), "domains": len(spec["domains"]), "builtin": True}
            continue
        # 已有抓取记录且不强制刷新 → 跳过
        prev = registry.get("sources", {}).get(name)
        if prev and not refresh:
            source_domains[name] = list(prev.get("domains", []))
            source_meta[name] = prev
            continue
        try:
            if spec["kind"] == "sspanel-csv-latest":
                text = fetch_latest_sspanel_csv(spec["url"])
            else:
                text = fetch_text(spec["url"])
            if spec["kind"] == "airports-json":
                domains = parse_airports_json(text)
            elif spec["kind"] in ("sspanel-csv", "sspanel-csv-latest"):
                include = set(spec.get("include_labels", []))
                include_ext = set(spec.get("include_labels_ext", []))
                domains = parse_sspanel_csv(text, include, include_ext)
            elif spec["kind"] == "markdown-with-code":
                domains = parse_markdown_with_codes(text)
            else:
                domains = parse_markdown_domains(text)
            source_domains[name] = domains
            source_meta[name] = {"fetched_at": now(), "domains": domains,
                                 "kind": spec["kind"],
                                 "csv": _LAST_CSV_NAME}
        except Exception as exc:
            print(f"  ! 源 {name} 抓取失败: {exc}")
            # 失败时用旧记录兜底
            if prev:
                source_domains[name] = list(prev.get("domains", []))
                source_meta[name] = prev
            else:
                source_domains[name] = []
                source_meta[name] = {"fetched_at": now(), "domains": [], "error": str(exc)}

    return source_domains, source_meta


def main() -> int:
    refresh = os.getenv("AIRPORTS_REFRESH", "") == "1"
    if os.getenv("AIRPORTS_RESET", "") == "1" and REGISTRY_FILE.exists():
        REGISTRY_FILE.unlink()
        print("[+] registry 已重置")

    registry = load_registry()
    source_domains, source_meta = collect_domains(refresh)

    # 汇总全部域名 → 归一化 → 与 registry 对比
    all_domains: dict[str, set[str]] = {}
    for name, domains in source_domains.items():
        for dom in domains:
            all_domains.setdefault(dom, set()).add(name)
    registry["sources"] = source_meta

    airports = registry["airports"]
    new_domains = [d for d in all_domains if d not in airports]
    known = [d for d in all_domains if d in airports]
    stale = [d for d in airports if d not in all_domains]

    print(f"[+] 聚合: {len(all_domains)} 域名 | 新增 {len(new_domains)} | "
          f"已知 {len(known)} | 源中消失 {len(stale)}")

    # 新增域名登记
    for dom in new_domains:
        airports[dom] = {
            "name": dom,
            "base": f"https://{dom}",
            "sources": sorted(all_domains[dom]),
            "first_seen": now(),
            "last_scanned": "",
            "status": "pending",
        }
    # SSPanel Mining 分类标签参考（不覆盖既有状态）
    for dom, label in _SSPANEL_LABELS.items():
        if dom in airports:
            airports[dom]["sspanel_mining_label"] = label
    # 邀请码参考（从注册链接提取）
    for dom, code in _INVITE_CODES.items():
        if dom in airports and not airports[dom].get("invite_code"):
            airports[dom]["invite_code"] = code
    # 已知域名补充来源
    for dom in known:
        airports[dom]["sources"] = sorted(
            set(airports[dom].get("sources", [])) | all_domains[dom]
        )

    # 扫描队列：白名单优先 + 新增，然后已知 pending/failed 重试
    whitelist = set(registry.get("whitelist", []))
    queue: list[str] = []
    for dom in sorted(all_domains):
        a = airports[dom]
        if dom in whitelist:
            queue.append(dom)
        elif a.get("status") in ("pending", "failed"):
            queue.append(dom)
    # 去重保序
    queue = list(dict.fromkeys(queue))
    print(f"[+] 扫描队列: {len(queue)} 个机场 "
          f"({sum(1 for d in queue if d in whitelist)} 白名单优先)")

    # 单个机场硬超时（探测+注册+拉节点），防止挂死整轮
    PER_AIRPORT_TIMEOUT = int(os.getenv("SCAN_PER_AIRPORT_TIMEOUT", "45"))
    CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "8"))

    def _scan_task(dom: str) -> dict:
        """并发任务：单个机场扫描（含线程超时，异常不外抛）。"""
        import threading

        result_box: dict = {}
        error_box: list = []

        def _inner():
            try:
                a = airports[dom]
                result_box.update(
                    scan.scan_one({"name": a.get("name", dom), "base": a["base"]})
                )
            except Exception as exc:  # noqa: BLE001
                error_box.append(str(exc))

        worker = threading.Thread(target=_inner, daemon=True)
        worker.start()
        worker.join(timeout=PER_AIRPORT_TIMEOUT)
        if worker.is_alive():
            error_box.append(f"timeout>{PER_AIRPORT_TIMEOUT}s")
        return {"result": result_box, "error": error_box[0] if error_box else None}

    scan.SCAN_ONLY_PROBE = os.getenv("SCAN_ONLY_PROBE", "") == "1"
    ok = 0

    if CONCURRENCY > 1 and len(queue) > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futures = {pool.submit(_scan_task, dom): dom for dom in queue}
            for future in as_completed(futures):
                dom = futures[future]
                a = airports[dom]
                print(f"--- {dom} [{a.get('status')}] ---")
                outcome = future.result()
                if outcome["error"]:
                    print(f"  ! {outcome['error']}")
                    a["status"] = "failed"
                    a["note"] = f"异常: {outcome['error']}"
                    save_registry(registry)
                    continue
                result = outcome["result"]
                a["last_scanned"] = now()
                a["probe"] = result.get("probe")
                a["probe_note"] = result.get("probe_note", "")
                links = result.get("links") or []
                a["node_count"] = result.get("node_count")
                a["link_count"] = result.get("link_count")
                if result.get("registered"):
                    a["registered"] = True
                    a["email_domain"] = result.get("email_domain")
                if result.get("plan"):
                    a["plan"] = result["plan"]
                if links:
                    a["status"] = "qualified"
                    a["note"] = result.get("note", "")
                    ok += 1
                elif result.get("probe"):
                    a["status"] = "failed"
                    a["note"] = result.get("note") or "SSPanel 但注册/登录/节点失败"
                else:
                    a["status"] = "excluded"
                    a["note"] = result.get("note") or "非 SSPanel vue 版"
                # 保存明细（仅 qualified 写 probe.json，排除/失败信息在 registry 足够）
                if a["status"] == "qualified":
                    probe_file = scan.NODES_DIR / f"scan_{scan._slug(a['name'])}.probe.json"
                    probe_file.write_text(
                        json.dumps({k: v for k, v in result.items() if k != "links"},
                                   ensure_ascii=False, indent=1) + "\n",
                        encoding="utf-8",
                    )
                    scan.save_subscription(
                        scan.NODES_DIR / f"scan_{scan._slug(a['name'])}_nodes.txt", links
                    )
                save_registry(registry)
    else:
        for dom in queue:
            a = airports[dom]
            print(f"--- {dom} [{a.get('status')}] ---")
            outcome = _scan_task(dom)
            if outcome["error"]:
                print(f"  ! {outcome['error']}")
                a["status"] = "failed"
                a["note"] = f"异常: {outcome['error']}"
                save_registry(registry)
                continue
            result = outcome["result"]
            a["last_scanned"] = now()
            a["probe"] = result.get("probe")
            a["probe_note"] = result.get("probe_note", "")
            links = result.get("links") or []
            a["node_count"] = result.get("node_count")
            a["link_count"] = result.get("link_count")
            if result.get("registered"):
                a["registered"] = True
                a["email_domain"] = result.get("email_domain")
            if result.get("plan"):
                a["plan"] = result["plan"]
            if links:
                a["status"] = "qualified"
                a["note"] = result.get("note", "")
                ok += 1
            elif result.get("probe"):
                a["status"] = "failed"
                a["note"] = result.get("note") or "SSPanel 但注册/登录/节点失败"
            else:
                a["status"] = "excluded"
                a["note"] = result.get("note") or "非 SSPanel vue 版"
            if a["status"] == "qualified":
                probe_file = scan.NODES_DIR / f"scan_{scan._slug(a['name'])}.probe.json"
                probe_file.write_text(
                    json.dumps({k: v for k, v in result.items() if k != "links"},
                               ensure_ascii=False, indent=1) + "\n",
                    encoding="utf-8",
                )
                scan.save_subscription(
                    scan.NODES_DIR / f"scan_{scan._slug(a['name'])}_nodes.txt", links
                )
            save_registry(registry)

    save_registry(registry)
    print(f"[+] 完成: 白名单 {len(registry['whitelist'])} 个 | 本次新增合格 {ok} 个")
    print(f"[+] registry: {REGISTRY_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
