import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location(
    "collect_airports", SCRIPTS / "collect_airports.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def test_parse_sspanel_csv_filters_labels():
    csv_text = "url,label\nhttps://a.com/auth/register,Normal\nhttps://b.com/auth/register,Email Validation\nhttps://c.com/auth/register,限制注册(邮箱)\nhttps://d.com/auth/register,GeeTest Validation\n"
    doms = module.parse_sspanel_csv(csv_text, {"Normal", "Email Validation"}, {"限制注册(邮箱)"})
    assert sorted(doms) == ["a.com", "b.com", "c.com"]
    assert module._SSPANEL_LABELS["a.com"] == "Normal"
    assert module._SSPANEL_LABELS["d.com"] == "GeeTest Validation"  # 标签全部记录


def test_parse_markdown_with_codes_extracts_invites():
    text = (
        "[山海官网](https://shanhai.me/#/register?code=CbE2YfJJ)\n"
        "[贝贝云](https://222.2beibei.com/#/register?code=Qb502cPh)\n"
        "裸链接 https://plain.example.com/auth/register\n"
    )
    module._INVITE_CODES.clear()
    doms = module.parse_markdown_with_codes(text)
    assert "shanhai.me" in doms
    assert "222.2beibei.com" in doms
    assert "plain.example.com" in doms
    assert module._INVITE_CODES.get("shanhai.me") == "CbE2YfJJ"
    assert module._INVITE_CODES.get("222.2beibei.com") == "Qb502cPh"


def test_skip_regex_not_kill_airports():
    # 常见机场域名不应被误杀
    for dom in ["dabai.in", "kuaizai.xyz", "xiaobai.network", "mgnet.vip",
                "xixicats.pw", "heduian.my", "7cc.buzz", "shanhai.me"]:
        assert not module._SKIP_RE.search(dom), f"{dom} 被误杀"
    # 明显的非机场仍应拦截
    assert module._SKIP_RE.search("github.com")
    assert module._SKIP_RE.search("t.me")


def test_clean_domain_normalization():
    assert module._clean_domain("WWW.Example.COM/") == "example.com"
    assert module._clean_domain("Example.COM/path?x=1") == "example.com"
    # 带端口/非域名字符会被正则拒绝（registry 以纯域名为键）
    assert module._clean_domain("www.example.com:443") == ""
    assert module._clean_domain("xn--4gq62f52gdss.top") == "xn--4gq62f52gdss.top"
    assert module._clean_domain("not a domain!!") == ""


def test_fetch_latest_sspanel_csv_picks_newest():
    """从 API 目录列表 JSON 里取文件名最新的 CSV。"""
    import json as _json

    fake_listing = _json.dumps([
        {"name": "mining_2023-01-01 00-00-00.csv"},
        {"name": "mining_2025-11-03 21-50-07.csv"},
        {"name": "mining_2025-11-03 21-21-56.csv"},
        {"name": "readme.md"},
    ])
    orig_fetch = module.fetch_text
    orig_urlopen = module.urllib.request.urlopen

    calls = []

    def fake_fetch(url):
        if url.startswith("https://api.github.com"):
            return fake_listing
        calls.append(url)
        return "url,label\nhttps://latest.com/auth/register,Normal\n"

    def fake_urlopen(req, timeout=25):
        raise AssertionError("should use fetch_text")

    module.fetch_text = fake_fetch
    module.urllib.request.urlopen = fake_urlopen
    try:
        text = module.fetch_latest_sspanel_csv("https://api.github.com/x")
        assert "latest.com" in text
        assert calls, "应下载 raw CSV"
        assert "mining_2025-11-03%2021-50-07" in calls[0], calls
        assert module._LAST_CSV_NAME == "mining_2025-11-03 21-50-07.csv"
    finally:
        module.fetch_text = orig_fetch
        module.urllib.request.urlopen = orig_urlopen


def test_registry_whitelist_roundtrip():
    import tempfile

    reg = {
        "version": 1,
        "updated_at": "",
        "sources": {},
        "airports": {
            "a.com": {"status": "qualified"},
            "b.com": {"status": "excluded"},
            "c.com": {"status": "qualified"},
        },
        "whitelist": [],
    }
    tmp = Path(tempfile.mkdtemp()) / "reg.json"
    orig_file = module.REGISTRY_FILE
    module.REGISTRY_FILE = tmp
    try:
        module.save_registry(reg)
        saved = json.loads(tmp.read_text())
        assert saved["whitelist"] == ["a.com", "c.com"]
    finally:
        module.REGISTRY_FILE = orig_file
