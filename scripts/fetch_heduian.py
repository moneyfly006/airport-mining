#!/usr/bin/env python3
"""HEduian (合点) 机场节点抓取脚本.

对应服务: heduian.my (SSPanel 后端, 免流机场)
- 登录: POST /auth/login {email, passwd, remember_me}
- 节点: GET /getnodelist (需登录 cookie)
- 协议: VMess(分号格式), Hysteria2(port= + obfs=salamander), Shadowsocks(plain)

节点格式说明 (raw_node.server 三种形态, 2026-08-26 实测 20 节点):
  1. "host;port;aid;net;;path=|host="        -> VMess (12 个)
  2. "host;port=30832&up_mbps=...&obfs=salamander&..." -> Hysteria2 (6 个)
  3. "s18.hdacd.com" (纯域名, method=aes-256-cfb) -> Shadowsocks (2 个)

SSPanel 的 user 对象提供:
  uuid    -> VMess/VLESS 通用 id
  passwd  -> Shadowsocks 密码 (及 Hysteria2 混淆密码)
  method  -> Shadowsocks 加密方式

用法:
  HEDUIAN_EMAIL=xxx HEDUIAN_PASSWORD=xxx python3 scripts/fetch_heduian.py
  缺省凭据从环境变量读取; 未设置时退出并提示 (不硬编码凭据).

环境变量:
  HEDUIAN_BASE_URL   网站地址 (默认 https://www.heduian.my)
  HEDUIAN_EMAIL      登录邮箱
  HEDUIAN_PASSWORD   登录密码

输出: nodes/heduian_nodes.txt (base64 订阅, 与仓库其他脚本一致)
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _fetch_node_common import save_subscription  # noqa: E402
from _repo_paths import NODES_DIR  # noqa: E402

SOURCE_NAME = "HEduian"
OUTPUT_FILE = NODES_DIR / "heduian_nodes.txt"
BASE_URL = os.getenv("HEDUIAN_BASE_URL", "https://www.heduian.my").rstrip("/")
EMAIL = os.getenv("HEDUIAN_EMAIL", "").strip()
PASSWORD = os.getenv("HEDUIAN_PASSWORD", "").strip()
TIMEOUT = int(os.getenv("HEDUIAN_TIMEOUT", "30"))

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def _request(
    session: urllib.request.OpenerDirector,
    path: str,
    method: str = "GET",
    data: dict[str, str] | None = None,
) -> str:
    headers = {
        "User-Agent": UA,
        "Referer": f"{BASE_URL}/auth/login",
        "Accept": "application/json, text/plain, */*",
    }
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(f"{BASE_URL}{path}", data=body, headers=headers, method=method)
    try:
        with session.open(request, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        raise RuntimeError(f"HTTP {exc.code} on {path}: {detail}") from exc


def login(session: urllib.request.OpenerDirector) -> None:
    if not EMAIL or not PASSWORD:
        raise ValueError(
            "HEDUIAN_EMAIL / HEDUIAN_PASSWORD 未设置 (凭据不硬编码, 请用环境变量提供)"
        )
    body = _request(
        session,
        "/auth/login",
        method="POST",
        data={"email": EMAIL, "passwd": PASSWORD, "remember_me": "on"},
    )
    data = parse_json(body)
    if data.get("ret") != 1:
        raise RuntimeError(f"登录失败: {data.get('msg', body[:120])}")


def parse_json(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"非 JSON 响应: {text[:120]}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"响应不是对象: {str(data)[:120]}")
    return data


def quote_tag(name: str) -> str:
    return urllib.parse.quote(str(name) or "Node")


def vmess_link(node: dict[str, Any], uuid: str) -> str:
    """SSPanel 分号格式: host;port;aid;net;;path=|host=..."""
    raw = str(node.get("server", ""))
    parts = raw.split(";")
    server = parts[0]
    port = parts[1] if len(parts) > 1 else ""
    aid = parts[2] if len(parts) > 2 and parts[2] else "0"
    net = parts[3] if len(parts) > 3 and parts[3] else "tcp"
    host, path = "", ""
    if len(parts) > 5 and parts[5]:
        for item in parts[5].split("|"):
            if item.startswith("path="):
                path = item[5:]
            elif item.startswith("host="):
                host = item[5:]
    if not (server and port and uuid):
        return ""
    config = {
        "v": "2",
        "ps": str(node.get("name") or "Node"),
        "add": server,
        "port": port,
        "id": uuid,
        "aid": aid,
        "scy": "auto",
        "net": net,
        "type": "none",
        "host": host,
        "path": path,
        "tls": "",
    }
    return "vmess://" + base64.b64encode(
        json.dumps(config, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def hysteria2_link(node: dict[str, Any], user: dict[str, Any]) -> str:
    """port=...&obfs=salamander&obfs_password=...&allow_insecure=1 格式.

    SSPanel 免流实现: obfs_password 是节点级混淆密码(作 hy2 auth),
    用户 passwd 作 obfs-password 参数。
    """
    raw = str(node.get("server", ""))
    parts = raw.split(";")
    server = parts[0]
    params: dict[str, str] = {}
    if len(parts) > 1:
        for item in parts[1].split("&"):
            if "=" in item:
                key, value = item.split("=", 1)
                params[key] = value
    port = params.get("port", "")
    obfs = params.get("obfs", "")
    obfs_password = params.get("obfs_password", params.get("obfs-password", ""))
    if not (server and port):
        return ""
    auth = obfs_password or str(user.get("passwd", ""))
    query: dict[str, str] = {}
    if params.get("allow_insecure") in ("1", "true"):
        query["insecure"] = "1"
    if obfs:
        query["obfs"] = obfs
    if user.get("passwd"):
        query["obfs-password"] = str(user["passwd"])
    for key in ("upmbps", "downmbps"):
        if params.get(key):
            query[key] = params[key]
    if params.get("sni") or params.get("serverName"):
        query["sni"] = params.get("sni") or params.get("serverName") or ""
    query_str = urllib.parse.urlencode({k: v for k, v in query.items() if v})
    suffix = f"?{query_str}" if query_str else ""
    return f"hysteria2://{urllib.parse.quote(auth, safe='')}@{server}:{port}{suffix}#{quote_tag(node.get('name', ''))}"


def shadowsocks_link(node: dict[str, Any], user: dict[str, Any]) -> str:
    """纯域名 plain 节点: SS (method + passwd)."""
    server = str(node.get("server", ""))
    method = str(node.get("method") or user.get("method") or "aes-256-gcm")
    password = str(user.get("passwd", ""))
    if not (server and password):
        return ""
    credentials = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
    return f"ss://{credentials}@{server}#{quote_tag(node.get('name', ''))}"


def node_link(node: dict[str, Any], user: dict[str, Any]) -> str:
    raw = str(node.get("server", ""))
    if raw.count(";") >= 3:
        return vmess_link(node, str(user.get("uuid", "")))
    if "port=" in raw:
        return hysteria2_link(node, user)
    return shadowsocks_link(node, user)


def extract_links(nodeinfo: dict[str, Any]) -> list[str]:
    user = nodeinfo.get("user") or {}
    if not isinstance(user, dict):
        user = {}
    # nodes_muport[0].user 提供真实 uuid/passwd (与 top-level user 相同, 双保险)
    muport = nodeinfo.get("nodes_muport")
    if isinstance(muport, list) and muport and isinstance(muport[0], dict):
        mu_user = muport[0].get("user") or {}
        if isinstance(mu_user, dict) and mu_user.get("uuid"):
            user = mu_user
    links: list[str] = []
    for node in nodeinfo.get("nodes", []):
        raw = node.get("raw_node") or node
        if not isinstance(raw, dict):
            continue
        link = node_link(raw, user)
        if link:
            links.append(link)
    return list(dict.fromkeys(links))


def main() -> int:
    # requests.Session 默认自动带 cookie; urllib 需显式挂 CookieProcessor,
    # 否则登录态丢失, getnodelist 返回 {"ret":-1}。
    session = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    try:
        login(session)
        print(f"[+] {SOURCE_NAME} 登录成功")
        body = _request(session, "/getnodelist")
        data = parse_json(body)
        if data.get("ret") != 1 or not isinstance(data.get("nodeinfo"), dict):
            raise RuntimeError(f"getnodelist 响应无效: {body[:150]}")
        links = extract_links(data["nodeinfo"])
    except Exception as exc:
        print(f"[-] {SOURCE_NAME} fetch failed: {exc}")
        return 1
    if not links:
        print(f"[-] {SOURCE_NAME} returned no supported proxy nodes")
        return 1
    save_subscription(OUTPUT_FILE, links)
    print(f"[+] saved {len(links)} {SOURCE_NAME} node(s): {OUTPUT_FILE.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
