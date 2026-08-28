import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location(
    "scan_sspanel_airports", SCRIPTS / "scan_sspanel_airports.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def test_load_airports_from_env_json():
    import os

    os.environ["SCAN_AIRPORTS"] = (
        '[{"name":"a","base":"https://a.com/"},{"name":"b","base":"b.com"}]'
    )
    os.environ.pop("SCAN_AIRPORTS_FILE", None)
    airports = module.load_airports()
    assert len(airports) == 2
    assert airports[0] == {"name": "a", "base": "https://a.com"}
    assert airports[1] == {"name": "b", "base": "https://b.com"}  # 自动补 https
    os.environ.pop("SCAN_AIRPORTS", None)


def test_load_airports_default_when_unset():
    import os

    os.environ.pop("SCAN_AIRPORTS", None)
    os.environ.pop("SCAN_AIRPORTS_FILE", None)
    airports = module.load_airports()
    assert len(airports) == len(module.DEFAULT_AIRPORTS)
    assert airports[0]["base"].startswith("https://")


def test_probe_detects_sspanel_vue():
    """{"ret":-1} 未登录响应 = SSPanel vue 版。"""
    captured = {}

    def fake_request(session, base, path, method="GET", data=None):
        captured["path"] = path
        if path == "/getnodelist":
            return 200, '{"ret":-1}'
        return 200, "{}"

    module._request = fake_request
    import urllib.request

    ok, note = module.probe(urllib.request.build_opener(), "https://x.com")
    assert ok is True
    assert '"ret":-1' in note
    assert captured["path"] == "/getnodelist"


def test_probe_rejects_html():
    def fake_request(session, base, path, method="GET", data=None):
        return 200, "<!DOCTYPE html><html></html>"

    module._request = fake_request
    import urllib.request

    ok, note = module.probe(urllib.request.build_opener(), "https://x.com")
    assert ok is False


def test_register_checks_ret_1():
    captured = {}

    def fake_request(session, base, path, method="GET", data=None):
        captured["path"] = path
        captured["data"] = data
        return 200, '{"ret":1,"msg":"注册成功"}'

    module._request = fake_request
    import urllib.request

    ok = module.register(urllib.request.build_opener(), "https://x.com", "a@163.com", "Pw123456!")
    assert ok is True
    assert captured["path"] == "/auth/register"
    assert captured["data"]["code"] == "0"
    assert captured["data"]["passwd"] == captured["data"]["repasswd"]


def test_fetch_nodes_reuses_heduian_parser():
    """SSPanel nodeinfo 结构 → 三协议链接（复用 fetch_heduian.extract_links）。"""
    nodeinfo = {
        "nodes": [
            {"raw_node": {"name": "ss1", "server": "s18.hdacd.com", "method": "aes-256-cfb"}},
            {"raw_node": {"name": "vm1", "server": "v10.zgtfqs.click;30807;2;tcp"}},
            {"raw_node": {"name": "hy1", "server": "v11.zgtfqs.click;port=30811&obfs=salamander&obfs_password=k&allow_insecure=1"}},
        ],
        "user": {"uuid": "u1", "passwd": "p1", "method": "chacha20-ietf", "plan": "A"},
    }

    def fake_request(session, base, path, method="GET", data=None):
        return 200, json.dumps({"ret": 1, "nodeinfo": nodeinfo})

    module._request = fake_request
    import urllib.request

    links, info = module.fetch_nodes(urllib.request.build_opener(), "https://x.com")
    assert len(links) == 3
    assert info["link_count"] == 3
    assert info["node_count"] == 3
    assert info["plan"] == "A"
    assert any(l.startswith("ss://") for l in links)
    assert any(l.startswith("vmess://") for l in links)
    assert any(l.startswith("hysteria2://") for l in links)


def test_scan_one_probe_only_mode():
    import os

    module.ONLY_PROBE = True
    try:
        result = module.scan_one({"name": "x", "base": "https://x.com"})
        assert "probe" in result
        assert result["registered"] is False
    finally:
        module.ONLY_PROBE = False
