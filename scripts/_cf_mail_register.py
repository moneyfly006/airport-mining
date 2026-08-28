#!/usr/bin/env python3
"""CF 邮箱全自动注册 — 副本脚本共享模块

包装 scripts/_cf_mail.py 的 CloudflareEmailProvider，给 fetch_*_cfmail.py
副本脚本提供三个能力：

  - new_email()               生成 前缀@域名 的 CF 无限邮箱
  - wait_code(email, timeout) 轮询收件箱提取 6 位数字验证码
  - wait_link(email, timeout) 轮询收件箱提取激活链接（验证邮件里的 http URL，
                              用于 faststunnel 这类「点击链接激活」的服务）

读信双通道（自动选择）：
  1. Worker API（_cf_mail.py 部署的 Email Worker）：需写权限的 CF 凭据，
     部署后 auth_token 自洽 —— 适合 CI（CF_MAIL_STATE 指向 runner.temp）。
  2. CF API Token 直读 KV（仅需读权限）：Worker 不可达/401 时自动回退，
     用 CF_API_TOKEN 直接读 Email Worker 的 KV namespace —— 适合本机调试。

环境变量：
  CF_API_TOKEN（或 CF_GLOBAL_KEY+CF_EMAIL）+ CF_EMAIL_DOMAIN  （部署用）
  CF_MAIL_STATE  可选，状态缓存路径（含 account_id / namespace_id / domain）

本模块是新增文件，不改动 _cf_mail.py / 原 fetch_*.py。
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _cf_mail import CfMailError, CloudflareEmailProvider, DeployState  # noqa: E402

_LINK_RE = re.compile(r"https?://[^\s\"'<>()\[\]\\)]+")
# 激活链接常见关键词（优先匹配）
_ACTIVATE_KEYWORDS = ("activate", "activation", "verify", "verification",
                      "active", "confirm", "token", "register", "signup", "auth")

# 验证码正则（先 6 位数字，再带 code/验证码 前缀的 6 位数字）
_CODE_PATTERNS = [
    re.compile(r"\b(\d{6})\b"),
    re.compile(r"(?:code|验证码)[^0-9]{0,20}[:：]?\s*(\d{6})", re.IGNORECASE),
]

_CF_API_ROOT = "https://api.cloudflare.com/client/v4"


def _qp_decode(text: str) -> str:
    """quoted-printable 解码（失败原样返回）。"""
    if "=" not in text:
        return text
    try:
        import quopri
        return quopri.decodestring(text.encode("utf-8")).decode("utf-8", "replace")
    except Exception:
        return text


class _KvInbox:
    """CF API Token 直读 KV 收件箱（Worker 401 时的回退通道，仅需读权限）。"""

    def __init__(self, token: str, account_id: str, namespace_id: str, domain: str):
        self.token = token
        self.account_id = account_id
        self.namespace_id = namespace_id
        self.domain = domain

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(
            _CF_API_ROOT + path, headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise CfMailError(f"CF KV API HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}") from exc

    def get_inbox(self, email: str) -> list[dict]:
        key = urllib.parse.quote("inbox:" + email.lower(), safe="")
        data = self._get(
            f"/accounts/{self.account_id}/storage/kv/namespaces/{self.namespace_id}/values/{key}"
        )
        return data if isinstance(data, list) else []

    def clear_inbox(self, email: str) -> None:
        # 只读 token 无法删除 KV；忽略（7 天自动过期）
        pass


class _KvProbe:
    """用只读 CF API Token 探测账户与 mailbox KV namespace（全新环境免状态文件）。"""

    def __init__(self, token: str):
        self.token = token

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(
            _CF_API_ROOT + path, headers={"Authorization": f"Bearer {self.token}"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def account_id(self) -> str:
        data = self._get("/accounts?per_page=5")
        accounts = data.get("result") or []
        if not accounts:
            raise CfMailError(f"CF API 无法枚举账户: {data.get('errors')}")
        return str(accounts[0]["id"])

    def find_mailbox_ns(self, account_id: str, domain: str) -> str:
        data = self._get(f"/accounts/{account_id}/storage/kv/namespaces?per_page=100")
        nss = data.get("result") or []
        domain_hint = (domain or "").split(".")[0]
        candidates = []
        for ns in nss:
            title = str(ns.get("title") or "").lower()
            if "mailbox" in title or "xx-nodes" in title:
                candidates.append((title, str(ns["id"])))
        for title, nid in candidates:
            if domain_hint and domain_hint in title:
                return nid
        if candidates:
            return candidates[0][1]
        raise CfMailError(
            f"CF API 未找到 mailbox KV namespace (domain={domain}): "
            f"{[n.get('title') for n in nss][:10]}"
        )


def _build_kv_reader() -> _KvInbox | None:
    """用 CF_API_TOKEN 构造 KV 直读器；优先状态文件，缺失时 CF API 探测。"""
    token = os.getenv("CF_API_TOKEN", "").strip()
    if not token:
        return None
    state = DeployState()
    account_id = state.get("account_id")
    namespace_id = state.get("namespace_id")
    domain = state.get("domain") or os.getenv("CF_EMAIL_DOMAIN", "").strip().lower()

    if not (account_id and namespace_id):
        try:
            probe = _KvProbe(token)
            if not account_id:
                account_id = probe.account_id()
                print(f"    [i] CF API 探测账户: {account_id}")
            if not namespace_id:
                namespace_id = probe.find_mailbox_ns(account_id, domain)
                print(f"    [i] CF API 探测 KV namespace: {namespace_id}")
        except Exception as exc:
            print(f"    [i] CF API 探测 KV 失败: {exc}", file=sys.stderr)
            return None

    if not (account_id and namespace_id and domain):
        print("    [i] 无法确定 account_id/namespace_id/domain，跳过 KV 直读", file=sys.stderr)
        return None
    return _KvInbox(token, account_id, namespace_id, domain)


class CfMailRegister:
    """CF 无限邮箱注册助手（读信自动选择 Worker API / KV 直读）。"""

    def __init__(self) -> None:
        self.provider: CloudflareEmailProvider | None = None
        self.kv: _KvInbox | None = None
        self.domain = ""

        # 通道 1：Worker API（部署/复用；读权限不足时 deploy 会失败）
        try:
            self.provider = CloudflareEmailProvider()
            self.domain = self.provider.domain or self.provider.state.get("domain")
            if not self.provider.client.health():
                print("[i] Worker API 不可达，尝试 CF API Token 直读 KV ...")
                self.provider = None
        except CfMailError as exc:
            print(f"[i] Worker 部署不可用（{exc}），尝试 CF API Token 直读 KV ...")
            self.provider = None

        # 通道 2：CF API Token 直读 KV（仅需读权限）—— 总是尝试构建，作回退
        self.kv = _build_kv_reader()

        if not self.domain:
            if self.kv is not None:
                self.domain = self.kv.domain
            else:
                self.domain = os.getenv("CF_EMAIL_DOMAIN", "").strip().lower()
        if not self.domain:
            raise CfMailError("无法确定 CF 邮箱域名（需 CF_EMAIL_DOMAIN 或有效状态文件）")
        if self.provider is None and self.kv is None:
            raise CfMailError(
                "读信通道不可用：需 CF_API_TOKEN（读 KV 权限）或可部署的 Worker 凭据"
            )
        print(f"[*] CF 邮箱域: *@{self.domain} "
              f"(worker={'可用' if self.provider else '不可用'}, kv={'可用' if self.kv else '无'})")

    # ------------------------------------------------------------------
    def new_email(self) -> str:
        if self.provider is not None:
            result = self.provider.create()
            if result:
                email, _ = result
                return email
        domain = self.domain or "icandoit.eu.org"
        import random
        import string
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        return f"mail{suffix}@{domain}"

    def _mails(self, email: str) -> tuple[list[dict], callable]:
        """返回 (邮件列表, 清空函数)。Worker 读信失败自动回退 KV 直读。"""
        if self.provider is not None:
            try:
                mails = self.provider.client.get_inbox(email)
                return mails, self.provider.client.clear_inbox
            except CfMailError as exc:
                print(f"    [i] Worker 读信失败（{exc}），回退 KV 直读")
                self.provider = None
        if self.kv is not None:
            return self.kv.get_inbox(email), self.kv.clear_inbox
        return [], lambda _e: None

    def wait_code(self, email: str, timeout: int = 150) -> str:
        """等 6 位数字验证码。超时返回空串。"""
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            time.sleep(5)
            try:
                mails, clear = self._mails(email)
            except CfMailError as exc:
                print(f"    [-] 读信失败: {exc}")
                continue
            for mail in mails:
                mid = str(mail.get("id") or "")
                if mid in seen:
                    continue
                seen.add(mid)
                code = _extract_code(mail)
                if code:
                    try:
                        clear(email)
                    except Exception:
                        pass
                    return code
        return ""

    def wait_link(self, email: str, timeout: int = 180) -> str:
        """等一封含 http(s) 链接的邮件，返回激活链接。超时返回空串。"""
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            time.sleep(5)
            try:
                mails, clear = self._mails(email)
            except CfMailError as exc:
                print(f"    [-] 读信失败: {exc}")
                continue
            for mail in mails:
                mid = str(mail.get("id") or "")
                if mid in seen:
                    continue
                seen.add(mid)
                # 正文可能是 quoted-printable 编码，先解码再提取链接（否则 URL 会被截断）
                parts = [
                    _qp_decode(str(mail.get(f) or ""))
                    for f in ("subject", "text", "html")
                ]
                text = " ".join(parts)
                links = _LINK_RE.findall(text)
                if not links:
                    continue
                link = next(
                    (l for l in links if any(k in l.lower() for k in _ACTIVATE_KEYWORDS)),
                    links[-1],
                )
                try:
                    clear(email)
                except Exception:
                    pass
                return link.rstrip(".,;:!?")
        return ""

    def cleanup(self, email: str | None = None) -> None:
        try:
            if self.provider is not None:
                self.provider.cleanup(email)
            elif self.kv is not None:
                self.kv.clear_inbox(email or "")
        except Exception:
            pass


def _extract_code(mail: dict) -> str:
    from _cf_mail import _extract_code_from_mail
    return _extract_code_from_mail(mail, _CODE_PATTERNS)
