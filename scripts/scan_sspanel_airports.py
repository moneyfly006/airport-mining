#!/usr/bin/env python3
"""SSPanel 机场批量扫描器 — 探测 + 自动注册 + 拉取节点（通用版）

方法论（不良林 getnodelist 教程 + 2026-08 实测扩展）：
  1. 探测：GET {domain}/getnodelist，未登录返回 {"ret":-1} 说明是 SSPanel vue 版
  2. 注册：POST /auth/register {email,name,passwd,repasswd,code:0}
     - 实测多数 SSPanel 机场无邮箱验证码、无邀请码（JS code 硬编码 0）
     - 优先 CF 无限邮箱（_cf_mail_register.py），域名被黑名单时自动降级
       随机 163/126/qq/outlook 邮箱（heduian 实测 icandoit.eu.org 被封）
  3. 登录：POST /auth/login {email,passwd}（保持 cookie）
  4. 拉节点：GET /getnodelist → nodeinfo.nodes[].raw_node.server 特征判断协议
     （VMess 分号格式 / Hysteria2 port=&obfs= / SS plain），用账号 uuid/passwd
     拼接链接 —— 解析复用 scripts/fetch_heduian.py

机场清单来源（按优先级）：
  - 环境变量 SCAN_AIRPORTS：JSON 数组 [{"name":"x","base":"https://x.com"}, ...]
  - 环境变量 SCAN_AIRPORTS_FILE：指向 JSON 文件
  - 内置默认清单（已实测 SSPanel 机场）
    heduian.my 等。GitHub 机场推荐仓库（jctz123/jichang-tuijian、
    everett7623/airport-recommendations-2026、KaWaIDeSuNe/dijiajichang 等）
    多为付费/短链跳转，未列入默认；有新 SSPanel 机场可加进 SCAN_AIRPORTS。

环境变量：
  SCAN_AIRPORTS / SCAN_AIRPORTS_FILE  机场清单（见上）
  SCAN_ONLY_PROBE=1                   只探测不注册（列出 SSPanel vue 版候选）
  SCAN_TIMEOUT                        单请求超时（默认 20s）
  CF_API_TOKEN / CF_EMAIL_DOMAIN 等   见 _cf_mail_register.py（可选）

输出：
  nodes/scan_<slug>_nodes.txt   每个成功机场一个文件（base64 订阅）
  nodes/scan_<slug>.probe.json  探测结果（vue 版标记 / 注册状态 / 节点数）
"""

from __future__ import annotations

import json
import os
import re
import secrets
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fetch_heduian as heduian  # noqa: E402  复用 SSPanel 解析
from _fetch_node_common import save_subscription  # noqa: E402
from _repo_paths import NODES_DIR  # noqa: E402

try:
    from _cf_mail_register import CfMailRegister  # noqa: E402
except ImportError:  # pragma: no cover
    CfMailRegister = None

# CF 邮箱注册器单例：只初始化一次（无凭据时会尝试部署/读 KV，每次实例化很慢）
_cf_register = None


def _get_cf_register():
    global _cf_register
    if _cf_register is None and CfMailRegister is not None:
        try:
            _cf_register = CfMailRegister()
        except Exception:
            _cf_register = False
    return _cf_register if _cf_register else None

SOURCE_NAME = "SSPanelScan"
TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "20"))
ONLY_PROBE = os.getenv("SCAN_ONLY_PROBE", "") == "1"

# 实测可注册的邮箱域（heduian 等 SSPanel 机场；icandoit.eu.org 被部分机场黑名单）
FALLBACK_DOMAINS = ("163.com", "126.com", "qq.com", "outlook.com")

DEFAULT_AIRPORTS = [
    {"name": "heduian", "base": "https://www.heduian.my"},
]


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_").lower()
    return slug or "airport"


def load_airports() -> list[dict]:
    airports: list[dict] = []
    raw = os.getenv("SCAN_AIRPORTS", "").strip()
    path = os.getenv("SCAN_AIRPORTS_FILE", "").strip()
    if raw:
        try:
            airports = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"SCAN_AIRPORTS 不是合法 JSON: {exc}") from exc
    elif path:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        lines = [l for l in text.splitlines() if not l.strip().startswith("//")]
        airports = json.loads("\n".join(lines))
    else:
        airports = list(DEFAULT_AIRPORTS)

    normalized = []
    for item in airports:
        if not isinstance(item, dict):
            continue
        base = str(item.get("base") or item.get("url") or "").strip().rstrip("/")
        name = str(item.get("name") or base).strip()
        if not base:
            continue
        if not base.startswith("http"):
            base = f"https://{base}"
        normalized.append({"name": name, "base": base})
    return normalized


def _session() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor())


def _request(
    session: urllib.request.OpenerDirector,
    base: str,
    path: str,
    method: str = "GET",
    data: dict[str, str] | None = None,
) -> tuple[int, str]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "Referer": f"{base}{path}",
        "Accept": "application/json, text/plain, */*",
    }
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["X-Requested-With"] = "XMLHttpRequest"
    request = urllib.request.Request(
        f"{base}{path}", data=body, headers=headers, method=method
    )
    try:
        with session.open(request, timeout=TIMEOUT) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        return exc.code, detail
    except Exception as exc:  # 网络错误（超时/DNS）不致命
        return 0, f"network error: {exc}"


def probe(session: urllib.request.OpenerDirector, base: str) -> tuple[bool, str]:
    """未登录访问 /getnodelist；{"ret":-1} 或 {"ret":0} = SSPanel vue 版。"""
    status, body = _request(session, base, "/getnodelist")
    if status != 200:
        return False, f"HTTP {status}"
    text = body.strip()
    if text.startswith("{") and '"ret"' in text:
        return True, text[:120]
    return False, text[:120]


def _random_email() -> str:
    local = "hd" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    return f"{local}@{secrets.choice(FALLBACK_DOMAINS)}"


def _random_password() -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12)) + "Aa1!"


def register(
    session: urllib.request.OpenerDirector, base: str, email: str, password: str
) -> bool:
    status, body = _request(
        session,
        base,
        "/auth/register",
        method="POST",
        data={
            "email": email,
            "name": email.split("@")[0],
            "passwd": password,
            "repasswd": password,
            "code": "0",
        },
    )
    if status != 200:
        return False
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    return data.get("ret") == 1


def login(
    session: urllib.request.OpenerDirector, base: str, email: str, password: str
) -> bool:
    status, body = _request(
        session,
        base,
        "/auth/login",
        method="POST",
        data={"email": email, "passwd": password, "remember_me": "on"},
    )
    if status != 200:
        return False
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    return data.get("ret") == 1


def fetch_nodes(
    session: urllib.request.OpenerDirector, base: str
) -> tuple[list[str], dict]:
    status, body = _request(session, base, "/getnodelist")
    if status != 200:
        return [], {"error": f"HTTP {status}"}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return [], {"error": "non-json"}
    if data.get("ret") != 1 or not isinstance(data.get("nodeinfo"), dict):
        return [], {"error": f"ret={data.get('ret')}"}
    nodeinfo = data["nodeinfo"]
    links = heduian.extract_links(nodeinfo)
    user = nodeinfo.get("user") or {}
    return links, {
        "node_count": len(nodeinfo.get("nodes", [])),
        "link_count": len(links),
        "plan": user.get("plan"),
        "transfer_enable": user.get("transfer_enable"),
        "email": user.get("email"),
    }


def scan_one(airport: dict) -> dict:
    name, base = airport["name"], airport["base"]
    slug = _slug(name)
    result: dict = {"name": name, "base": base, "probe": False, "registered": False,
                    "login": False, "links": [], "note": ""}
    session = _session()

    is_sspanel, probe_note = probe(session, base)
    result["probe"] = is_sspanel
    result["probe_note"] = probe_note
    if not is_sspanel:
        result["note"] = f"非 SSPanel vue 版: {probe_note}"
        return result
    if ONLY_PROBE:
        return result

    # 注册：优先 CF 邮箱（单例，只初始化一次），失败降级随机邮箱
    email, password = "", ""
    cf_reg = _get_cf_register()
    if cf_reg is not None:
        try:
            email = cf_reg.new_email()
            password = _random_password()
            if register(session, base, email, password):
                result["registered"] = True
                result["email_domain"] = email.split("@")[1]
        except Exception:
            email, password = "", ""

    if not result["registered"]:
        email, password = _random_email(), _random_password()
        if register(session, base, email, password):
            result["registered"] = True
            result["email_domain"] = email.split("@")[1]
        else:
            result["note"] = "注册失败（可能需要邀请码/验证码/域名黑名单）"
            return result

    if not login(session, base, email, password):
        result["note"] = "注册成功但登录失败"
        return result
    result["login"] = True

    links, info = fetch_nodes(session, base)
    result["links"] = links
    result.update(info)
    if not links:
        result["note"] = "登录成功但无可用节点（可能无试用流量）"
    return result


def main() -> int:
    airports = load_airports()
    print(f"[+] {SOURCE_NAME}: {len(airports)} 个机场待扫描"
          f"{'（仅探测）' if ONLY_PROBE else ''}")
    ok = 0
    for airport in airports:
        print(f"--- {airport['name']} {airport['base']} ---")
        try:
            result = scan_one(airport)
        except Exception as exc:
            print(f"  ! 异常: {exc}")
            continue
        slug = _slug(result["name"])
        print(f"  probe(SSPanel)={result.get('probe')} "
              f"registered={result.get('registered')} "
              f"login={result.get('login')} links={len(result.get('links', []))}")
        if result.get("note"):
            print(f"  note: {result['note']}")

        # 保存探测信息
        probe_file = NODES_DIR / f"scan_{slug}.probe.json"
        probe_file.write_text(
            json.dumps({k: v for k, v in result.items() if k != "links"},
                       ensure_ascii=False, indent=1) + "\n",
            encoding="utf-8",
        )
        # 保存节点
        links = result.get("links") or []
        if links:
            save_subscription(NODES_DIR / f"scan_{slug}_nodes.txt", links)
            ok += 1
    print(f"[+] {SOURCE_NAME}: {ok}/{len(airports)} 个机场出节点")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
