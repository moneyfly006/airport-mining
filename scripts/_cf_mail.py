#!/usr/bin/env python3
"""Cloudflare 无限邮箱 — 自动部署 + 程序化读信 Provider

基于 tech-shrimp《白嫖Cloudflare无限多企业邮箱》方案落地：
  1. 域名托管到 Cloudflare，启用 Email Routing
  2. catch-all 规则指向 Email Worker（本模块自动部署）
  3. 任意 `前缀@你的域名` 邮件都被 Worker 存入 KV
  4. 脚本通过 Worker HTTP API 读信 → 提取验证码

本模块提供：
  - deploy_cf_mail(): 用 CF API token 幂等部署（Worker + KV + Email Routing）
  - CloudflareEmailProvider: 实现 fetch_departures 需要的 TempMailProvider 接口
    （create 生成任意前缀邮箱，wait_code 轮询 Worker API 提取验证码）

环境变量：
  CF_API_TOKEN     必填（二选一）：Cloudflare API Token
                   建议权限：Workers Scripts Edit、Workers KV Storage Edit、
                   Email Routing Addresses Edit、Zone Edit、Account Settings Read
  CF_GLOBAL_KEY    必填（二选一）：Cloudflare Global API Key（需配合 CF_EMAIL）
  CF_EMAIL         使用 Global API Key 时必填：Cloudflare 账户登录邮箱
  CF_EMAIL_DOMAIN  必填：收信域名（已托管到 Cloudflare）
  CF_ACCOUNT_ID    可选：自动探测
  CF_ZONE_ID       可选：自动探测
  CF_WORKER_NAME   可选：Worker 名称（默认 xx-nodes-cf-mail）
  CF_AUTH_TOKEN    可选：读信 API 密钥（默认随机生成，存于 Worker secret）
  CF_MAIL_STATE    可选：状态缓存文件路径（默认 ~/.cf_mail_state.json）

CLI：
  python scripts/_cf_mail.py deploy            # 部署/确保（幂等）
  python scripts/_cf_mail.py status            # 查看部署状态
  python scripts/_cf_mail.py inbox <email>     # 查看某邮箱收件箱
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid as uuid_mod
from pathlib import Path
from typing import Any

# 与 cf_email_worker.js 保持同目录
WORKER_FILE = Path(__file__).resolve().parent / "cf_email_worker.js"
API_ROOT = "https://api.cloudflare.com/client/v4"
TIMEOUT = int(os.getenv("CF_MAIL_TIMEOUT", "30"))

# 兼容 fetch_departures 的 wait_code 正则（可在环境变量覆盖）
CODE_PATTERNS = [
    re.compile(r"code[^0-9]{0,20}[:：]?\s*(\d{6})", re.IGNORECASE),
    re.compile(r"验证码[:：]?\s*(\d{6})", re.IGNORECASE),
    re.compile(r"\b(\d{6})\b"),
]


def _extract_code_from_mail(mail: dict, patterns: list[re.Pattern]) -> str:
    """从一封邮件中提取验证码。

    1) 有 raw 时用标准库 email 解析（兼容 nested multipart / base64 / QP）
    2) 无 raw 时回退到 Worker 预解析的 text / html / subject
    """
    def match_all(text: str) -> str:
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                return m.group(1)
        return ""

    raw = str(mail.get("raw") or "")
    if raw:
        try:
            from email import policy
            from email.parser import BytesParser
            msg = BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8", errors="replace"))
            # 递归收集所有文本部分（text/plain 优先，其次 text/html）
            bodies: list[str] = []

            def walk(part) -> None:
                if part.is_multipart():
                    for sub in part.iter_parts():
                        walk(sub)
                    return
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        payload = part.get_content()
                        if isinstance(payload, str):
                            bodies.append(payload)
                    except Exception:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                bodies.append(payload.decode("utf-8", errors="replace"))
                        except Exception:
                            pass

            walk(msg)
            # text/plain 优先（bodies 按遍历序，plain 通常在前）
            for body in bodies:
                code = match_all(body)
                if code:
                    return code
            subject = str(msg.get("subject") or "")
            return match_all(subject)
        except Exception:
            pass  # raw 解析失败，回退预解析字段

    for field in ("text", "html", "subject"):
        code = match_all(str(mail.get(field) or ""))
        if code:
            return code
    return ""


class CfMailError(RuntimeError):
    """部署/读信错误（含 API 原始信息）。"""


# ---------------------------------------------------------------------------
# 底层 CF API 封装
# ---------------------------------------------------------------------------

class CfApi:
    """Cloudflare API v4 客户端。

    支持两种认证：
      - API Token:      Authorization: Bearer <CF_API_TOKEN>
      - Global Key:     X-Auth-Email: <CF_EMAIL> + X-Auth-Key: <CF_GLOBAL_KEY>
    """

    def __init__(self, token: str, email: str = ""):
        self.token = token
        self.email = email
        self.global_key = os.getenv("CF_GLOBAL_KEY", "").strip()

    def _auth_headers(self) -> dict:
        # Global API Key 优先（更宽松的凭据），否则 Bearer token
        if self.email and self.global_key:
            return {"X-Auth-Email": self.email, "X-Auth-Key": self.global_key}
        return {"Authorization": f"Bearer {self.token}"}

    def request(self, method: str, path: str, data: Any = None,
                headers: dict | None = None, raw_body: bytes | None = None,
                content_type: str | None = None) -> dict:
        url = f"{API_ROOT}{path}"
        hdrs = {
            "User-Agent": "xx-nodes-cf-mail/1.0",
        }
        hdrs.update(self._auth_headers())
        body = None
        if raw_body is not None:
            body = raw_body
            hdrs["Content-Type"] = content_type or "application/octet-stream"
        elif data is not None:
            body = json.dumps(data).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"errors": [{"message": raw[:300]}]}
            raise CfMailError(
                f"CF API {method} {path} -> HTTP {exc.code}: "
                f"{json.dumps(parsed.get('errors', parsed), ensure_ascii=False)[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise CfMailError(f"CF API {method} {path} 网络错误: {exc}") from exc

    def get(self, path: str) -> dict:
        return self.request("GET", path)

    def post(self, path: str, data: Any = None) -> dict:
        return self.request("POST", path, data=data)

    def put(self, path: str, data: Any = None) -> dict:
        return self.request("PUT", path, data=data)

    @staticmethod
    def _check(resp: dict, ctx: str) -> dict:
        if not resp.get("success"):
            raise CfMailError(
                f"{ctx} 失败: {json.dumps(resp.get('errors', resp), ensure_ascii=False)[:500]}"
            )
        return resp.get("result")


# ---------------------------------------------------------------------------
# 部署状态
# ---------------------------------------------------------------------------

class DeployState:
    """本地缓存部署产物（幂等复用），避免每次重复调用 CF API。"""

    FIELDS = ("account_id", "zone_id", "namespace_id", "script_name",
              "auth_token", "worker_url", "domain", "worker_hash")

    def __init__(self, path: Path | None = None):
        if path is None:
            path = Path(os.getenv("CF_MAIL_STATE", "~/.cf_mail_state.json")).expanduser()
        self.path = path
        self.data: dict[str, str] = {}
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
            except Exception:
                self.data = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")

    def get(self, key: str) -> str:
        return str(self.data.get(key, ""))

    def set(self, key: str, value: Any) -> None:
        if value is not None:
            self.data[key] = str(value)

    def is_valid(self, domain: str) -> bool:
        return (
            self.get("domain") == domain
            and all(self.get(f) for f in ("account_id", "zone_id", "namespace_id",
                                          "script_name", "auth_token", "worker_url"))
        )


# ---------------------------------------------------------------------------
# 部署逻辑（幂等）
# ---------------------------------------------------------------------------

def _random_token() -> str:
    return uuid_mod.uuid4().hex + uuid_mod.uuid4().hex


def _random_suffix() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=10))


def _read_worker_js() -> str:
    if not WORKER_FILE.exists():
        raise CfMailError(f"找不到 Worker 文件: {WORKER_FILE}")
    return WORKER_FILE.read_text(encoding="utf-8")


def _build_multipart(metadata: dict, script: str, script_name: str) -> tuple[bytes, str]:
    """构造 Workers API 上传所需的 multipart/form-data。

    ES module Worker 上传约定（对齐 cloudflare-go 官方实现）：
      - metadata part：name="metadata"，Content-Type: application/json
      - script part：name 与 main_module 相同（worker.mjs），
        filename 与 name 相同，Content-Type: application/javascript+module
        （+module 后缀是 CF 识别 ES module 语法的关键信号）
    """
    boundary = "----cfmail" + uuid_mod.uuid4().hex
    meta_part = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="metadata"\r\n'
        f"Content-Type: application/json\r\n\r\n"
        f"{json.dumps(metadata)}\r\n"
    ).encode("utf-8")
    script_part = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{script_name}"; filename="{script_name}"\r\n'
        f"Content-Type: application/javascript+module\r\n\r\n"
    ).encode("utf-8") + script.encode("utf-8") + b"\r\n"
    end = f"--{boundary}--\r\n".encode("utf-8")
    return meta_part + script_part + end, f"multipart/form-data; boundary={boundary}"


def _find_zone(api: CfApi, domain: str) -> str:
    resp = api.get(f"/zones?name={urllib.parse.quote(domain)}&per_page=50")
    result = CfApi._check(resp, "查询 zone")
    zones = result if isinstance(result, list) else []
    for zone in zones:
        if zone.get("name") == domain:
            if zone.get("status") != "active":
                raise CfMailError(
                    f"域名 {domain} 状态为 {zone.get('status')}，"
                    f"需先在 Cloudflare 完成激活（Nameserver 生效）"
                )
            return str(zone["id"])
    raise CfMailError(
        f"域名 {domain} 不在该 Token 可访问的 zone 中，"
        f"请确认域名已托管到 Cloudflare 且 Token 含 Zone 权限"
    )


def _ensure_email_routing(api: CfApi, zone_id: str) -> None:
    """启用 Email Routing 并添加 DNS 记录（幂等）。"""
    try:
        resp = api.get(f"/zones/{zone_id}/email/routing")
        state = CfApi._check(resp, "查询 Email Routing 状态")
        if state.get("enabled"):
            return
    except CfMailError:
        pass  # 未启用则尝试启用
    print("  [*] 启用 Email Routing ...")
    CfApi._check(api.post(f"/zones/{zone_id}/email/routing/enable"), "启用 Email Routing")
    print("  [*] 添加 Email Routing DNS 记录（MX/SPF/DKIM）...")
    CfApi._check(api.post(f"/zones/{zone_id}/email/routing/dns"), "添加 DNS 记录")


def _ensure_kv_namespace(api: CfApi, account_id: str, title: str) -> str:
    resp = api.get(f"/accounts/{account_id}/storage/kv/namespaces?per_page=100")
    result = CfApi._check(resp, "查询 KV namespace")
    for ns in (result if isinstance(result, list) else []):
        if ns.get("title") == title:
            return str(ns["id"])
    print(f"  [*] 创建 KV namespace: {title} ...")
    resp = api.post(f"/accounts/{account_id}/storage/kv/namespaces", {"title": title})
    result = CfApi._check(resp, "创建 KV namespace")
    return str(result["id"])


def _upload_worker(api: CfApi, account_id: str, script_name: str,
                   namespace_id: str, auth_token: str) -> None:
    script = _read_worker_js()
    module_name = "worker.mjs"
    metadata = {
        "main_module": module_name,  # 与 script part 的 name/filename 一致
        "compatibility_date": "2024-09-01",
        "bindings": [
            {"type": "kv_namespace", "name": "MAILBOX", "namespace_id": namespace_id},
            {"type": "secret_text", "name": "AUTH_TOKEN", "text": auth_token},
        ],
    }
    body, ctype = _build_multipart(metadata, script, module_name)
    print(f"  [*] 上传 Worker 脚本: {script_name} ...")
    resp = api.request("PUT", f"/accounts/{account_id}/workers/scripts/{script_name}",
                       raw_body=body, content_type=ctype)
    CfApi._check(resp, "上传 Worker")


def _set_catch_all_rule(api: CfApi, zone_id: str, script_name: str) -> None:
    """catch-all 规则 → worker（文章方案的核心：无限邮箱入口）。"""
    payload = {
        "enabled": True,
        "matchers": [{"type": "all"}],
        "actions": [{"type": "worker", "value": [script_name]}],
    }
    print("  [*] 设置 catch-all 规则 -> Email Worker ...")
    CfApi._check(api.put(f"/zones/{zone_id}/email/routing/rules/catch_all", payload),
                 "设置 catch-all 规则")


def _ensure_custom_route(api: CfApi, zone_id: str, domain: str, script_name: str) -> str:
    """创建 mail.{domain} 自定义路由 + DNS 记录，返回读信 API base URL。

    workers.dev 子域路由在新版 API 下经常未启用（error 1042），自定义路由
    更稳定：mail.{domain}/* → worker（proxied，worker 直接接管）。
    """
    host = f"mail.{domain}"
    pattern = f"{host}/*"

    # 1) 查已有路由（幂等）
    resp = api.get(f"/zones/{zone_id}/workers/routes")
    routes = CfApi._check(resp, "查询 workers routes")
    for route in routes if isinstance(routes, list) else []:
        if route.get("pattern") == pattern:
            print(f"  [*] 复用自定义路由: {pattern}")
            return f"https://{host}"

    # 2) 创建路由
    print(f"  [*] 创建自定义路由: {pattern} -> {script_name}")
    resp = api.post(f"/zones/{zone_id}/workers/routes",
                    {"pattern": pattern, "script": script_name})
    CfApi._check(resp, "创建自定义路由")

    # 3) 确保 DNS 记录存在（proxied A 记录，worker 接管流量）
    dns_host = f"{host}."
    resp = api.get(f"/zones/{zone_id}/dns_records?name={urllib.parse.quote(host)}")
    records = CfApi._check(resp, "查询 DNS 记录")
    exists = any(
        r.get("name") == host and r.get("type") == "A" and r.get("proxied")
        for r in (records if isinstance(records, list) else [])
    )
    if not exists:
        print(f"  [*] 添加 DNS 记录: {host} A -> Cloudflare (proxied)")
        api.post(f"/zones/{zone_id}/dns_records",
                 {"type": "A", "name": host, "content": "192.0.2.1",
                  "proxied": True, "ttl": 1})
    return f"https://{host}"


def _get_worker_url(api: CfApi, account_id: str, script_name: str) -> str:
    # workers.dev 子域在 /workers/subdomain 端点（Global Key 也能访问）
    resp = api.get(f"/accounts/{account_id}/workers/subdomain")
    result = CfApi._check(resp, "查询 workers.dev 子域")
    subdomain = result.get("subdomain") or ""
    if not subdomain:
        raise CfMailError("无法获取 workers.dev 子域（Token 需 Workers Subdomain 读权限）")
    return f"https://{script_name}.{subdomain}.workers.dev"


def deploy_cf_mail(force: bool = False) -> DeployState:
    """幂等部署 Cloudflare 无限邮箱，返回部署状态。

    force=True 时忽略本地状态缓存并强制重传。
    """
    token = os.getenv("CF_API_TOKEN", "").strip()
    global_key = os.getenv("CF_GLOBAL_KEY", "").strip()
    email = os.getenv("CF_EMAIL", "").strip()
    domain = os.getenv("CF_EMAIL_DOMAIN", "").strip().lower()
    if not token and not (global_key and email):
        raise CfMailError("缺少凭据：需 CF_API_TOKEN，或 CF_GLOBAL_KEY + CF_EMAIL")
    if global_key and not email:
        raise CfMailError("使用 CF_GLOBAL_KEY 时必须同时设置 CF_EMAIL（Cloudflare 账户登录邮箱）")
    if not domain:
        raise CfMailError("缺少 CF_EMAIL_DOMAIN 环境变量")

    state = DeployState()
    if not force and state.is_valid(domain):
        print(f"[*] 复用已有部署状态: {state.path} (worker: {state.get('worker_url')})")
        return state

    api = CfApi(token, email=email)

    # 1) 账户
    account_id = os.getenv("CF_ACCOUNT_ID", "").strip() or state.get("account_id")
    if not account_id:
        resp = api.get("/accounts?per_page=50")
        result = CfApi._check(resp, "查询账户")
        accounts = result if isinstance(result, list) else []
        if not accounts:
            raise CfMailError("Token 无法访问任何账户（需 Account Settings Read 权限）")
        account_id = str(accounts[0]["id"])
        print(f"  [*] 账户: {accounts[0].get('name', account_id)} ({account_id})")
    state.set("account_id", account_id)

    # 2) zone
    zone_id = os.getenv("CF_ZONE_ID", "").strip() or state.get("zone_id")
    if not zone_id:
        zone_id = _find_zone(api, domain)
        print(f"  [*] zone: {domain} ({zone_id})")
    state.set("zone_id", zone_id)

    # 3) Email Routing + DNS
    _ensure_email_routing(api, zone_id)

    # 4) KV namespace
    namespace_title = f"{domain}-mailbox"
    namespace_id = state.get("namespace_id")
    if not namespace_id or force:
        namespace_id = _ensure_kv_namespace(api, account_id, namespace_title)
    state.set("namespace_id", namespace_id)

    # 5) Worker 脚本
    script_name = os.getenv("CF_WORKER_NAME", "").strip() or "xx-nodes-cf-mail"
    auth_token = os.getenv("CF_AUTH_TOKEN", "").strip() or state.get("auth_token") or _random_token()
    state.set("script_name", script_name)
    state.set("auth_token", auth_token)

    worker_hash = _read_worker_js().strip()
    if force or state.get("worker_hash") != worker_hash or not state.get("worker_url"):
        _upload_worker(api, account_id, script_name, namespace_id, auth_token)
        state.set("worker_hash", worker_hash)
    else:
        print(f"  [*] Worker 脚本未变化，跳过上传")

    # 6) catch-all 规则
    _set_catch_all_rule(api, zone_id, script_name)

    # 7) 读信 API base：自定义路由 mail.{domain} 优先，workers.dev 兜底
    worker_url = state.get("worker_url")
    if not worker_url or force:
        try:
            worker_url = _ensure_custom_route(api, zone_id, domain, script_name)
        except CfMailError as exc:
            print(f"  [!] 自定义路由失败（{exc}），回退 workers.dev ...")
            worker_url = _get_worker_url(api, account_id, script_name)
    state.set("worker_url", worker_url)

    state.set("domain", domain)
    state.save()
    print(f"[+] Cloudflare 无限邮箱部署完成")
    print(f"    worker: {worker_url}")
    print(f"    邮箱域: *@{domain}  (catch-all)")
    print(f"    状态缓存: {state.path}")
    return state


# ---------------------------------------------------------------------------
# 读信 API 客户端
# ---------------------------------------------------------------------------

class CfMailClient:
    """通过 Worker HTTP API 读信。"""

    UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

    def __init__(self, state: DeployState):
        self.base = state.get("worker_url").rstrip("/")
        self.auth_token = state.get("auth_token")

    def _headers(self) -> dict:
        # 浏览器 UA 规避 Cloudflare Bot Fight Mode（error 1010）
        return {"Authorization": f"Bearer {self.auth_token}", "User-Agent": self.UA}

    def get_inbox(self, email: str) -> list[dict]:
        url = f"{self.base}/api/inbox?email={urllib.parse.quote(email)}"
        req = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise CfMailError(f"读信 API HTTP {exc.code}: {raw[:300]}") from exc
        except urllib.error.URLError as exc:
            raise CfMailError(f"读信 API 网络错误: {exc}") from exc
        mails = data.get("mails") if isinstance(data, dict) else None
        return mails if isinstance(mails, list) else []

    def clear_inbox(self, email: str) -> None:
        url = f"{self.base}/api/inbox?email={urllib.parse.quote(email)}"
        req = urllib.request.Request(url, headers=self._headers(), method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT):
                pass
        except Exception:
            pass

    def health(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.base}/api/health", headers=self._headers())
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.status == 200
        except Exception:
            return False


# ---------------------------------------------------------------------------
# 无限邮箱 Provider（fetch_departures 使用）
# ---------------------------------------------------------------------------

class CloudflareEmailProvider:
    """无限邮箱：任意前缀@域名即收件箱（catch-all 生效，无需预创建）。"""

    name = "cloudflare"

    def __init__(self, state: DeployState | None = None):
        self.state = state or deploy_cf_mail()
        self.client = CfMailClient(self.state)
        self.domain = self.state.get("domain")

    def create(self) -> tuple[str, str] | None:
        """生成 前缀@域名 邮箱。返回 (email, token=email)。"""
        domain = getattr(self, "domain", "") or self.state.get("domain")
        if not domain:
            return None
        email = f"mail{_random_suffix()}@{domain}"
        return email, email

    def wait_code(self, token: str, timeout: int = 120) -> str:
        """轮询 Worker API，从最新邮件中提取验证码。

        优先用原始 MIME（标准库 email 精确解析，兼容 nested multipart）；
        无 raw 时回退到 Worker 预解析的 text/html/subject 字段。
        """
        email = token
        patterns = CODE_PATTERNS
        extra = os.getenv("CF_MAIL_CODE_PATTERN", "").strip()
        if extra:
            try:
                patterns = [re.compile(extra, re.IGNORECASE)] + patterns
            except re.error:
                pass

        deadline = time.time() + timeout
        seen_ids: set[str] = set()
        while time.time() < deadline:
            time.sleep(5)
            try:
                mails = self.client.get_inbox(email)
            except CfMailError as exc:
                print(f"    [-] 读信失败: {exc}")
                continue
            for mail in mails:
                mail_id = str(mail.get("id") or "")
                if mail_id in seen_ids:
                    continue
                seen_ids.add(mail_id)
                code = _extract_code_from_mail(mail, patterns)
                if code:
                    self.client.clear_inbox(email)
                    return code
        return ""

    def cleanup(self, email: str | None = None) -> None:
        """用完删除邮箱：清空该地址的全部邮件数据（catch-all 下邮箱即收件箱）。"""
        try:
            self.client.clear_inbox(email or "")
        except Exception as exc:  # 清理失败不阻塞主流程
            print(f"    [!] 邮箱清理失败（{exc}），可稍后手动 clear")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_inbox(args: argparse.Namespace) -> int:
    state = _get_state_or_die()
    client = CfMailClient(state)
    mails = client.get_inbox(args.email)
    print(f"[*] {args.email} 收件箱: {len(mails)} 封")
    for mail in mails[:10]:
        print(f"  - {mail.get('date', '')} | {mail.get('from', '')} | {mail.get('subject', '')}")
        text = (mail.get("text") or "")[:200].replace("\n", " ")
        if text:
            print(f"    {text}")
    return 0


def _get_state_or_die() -> DeployState:
    state = DeployState()
    if not (state.get("domain") and state.get("worker_url")):
        print("[-] 尚无有效部署状态，先运行 deploy", file=sys.stderr)
        raise SystemExit(1)
    return state


def _cmd_create(args: argparse.Namespace) -> int:
    """生成一个新邮箱。stdout 只输出 email 一行，供脚本解析。"""
    try:
        provider = CloudflareEmailProvider()
    except CfMailError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    result = provider.create()
    if not result:
        print("[-] 邮箱生成失败", file=sys.stderr)
        return 1
    email, _ = result
    print(email)  # stdout：仅邮箱
    return 0


def _cmd_wait_code(args: argparse.Namespace) -> int:
    """轮询等待验证码。stdout 只输出 code 一行；超时返回非 0。"""
    try:
        provider = CloudflareEmailProvider()
    except CfMailError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    code = provider.wait_code(args.email, timeout=args.timeout)
    if not code:
        print(f"[-] 等待验证码超时（{args.timeout}s）", file=sys.stderr)
        return 1
    print(code)  # stdout：仅验证码
    return 0


def _cmd_clear(args: argparse.Namespace) -> int:
    state = _get_state_or_die()
    client = CfMailClient(state)
    client.clear_inbox(args.email)
    print(f"[+] 已清空 {args.email}", file=sys.stderr)
    return 0


def _cmd_health(args: argparse.Namespace) -> int:
    state = _get_state_or_die()
    client = CfMailClient(state)
    if client.health():
        print("ok")
        return 0
    print("[-] Worker 不可达", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cloudflare 无限邮箱服务：部署 / 生成邮箱 / 等待验证码",
        epilog="例: python cf_mail.py create | python cf_mail.py wait-code mailxxx@example.com --timeout 120",
    )
    sub = parser.add_subparsers(dest="cmd")

    p_deploy = sub.add_parser("deploy", help="部署/确保（幂等）")
    p_deploy.add_argument("--force", action="store_true", help="强制重传 Worker")

    sub.add_parser("status", help="查看部署状态")

    sub.add_parser("create", help="生成一个新邮箱（stdout 输出 email）")

    p_wait = sub.add_parser("wait-code", help="轮询等待验证码（stdout 输出 code）")
    p_wait.add_argument("email", help="收件邮箱（create 的输出）")
    p_wait.add_argument("--timeout", type=int, default=120, help="最长等待秒数（默认 120）")

    p_inbox = sub.add_parser("inbox", help="查看某邮箱收件箱")
    p_inbox.add_argument("email", help="完整邮箱地址")

    p_clear = sub.add_parser("clear", help="清空某邮箱收件箱")
    p_clear.add_argument("email", help="完整邮箱地址")

    sub.add_parser("health", help="检查读信 Worker 是否可达")

    args = parser.parse_args()

    if args.cmd == "deploy":
        try:
            deploy_cf_mail(force=args.force)
        except CfMailError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 1
        return 0

    if args.cmd == "status":
        state = DeployState()
        if state.get("domain") and state.get("worker_url"):
            print(f"[+] 已部署 (domain={state.get('domain')})")
            print(f"    worker: {state.get('worker_url')}")
            print(f"    state:  {state.path}")
        else:
            print("[-] 未部署，先运行 deploy")
        return 0

    if args.cmd == "create":
        return _cmd_create(args)

    if args.cmd == "wait-code":
        return _cmd_wait_code(args)

    if args.cmd == "inbox":
        return _cmd_inbox(args)

    if args.cmd == "clear":
        return _cmd_clear(args)

    if args.cmd == "health":
        return _cmd_health(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
