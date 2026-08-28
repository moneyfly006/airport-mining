#!/usr/bin/env python3
import base64
import json
import re
import urllib.parse
from pathlib import Path
from _repo_paths import NODES_DIR


LINK_RE = re.compile(
    r"(?i)\b(?:ss|ssr|vmess|vless|trojan|hysteria2|hysteria|hy2|socks|socks5|wireguard)://[^\s\"'<>\\]+"
)


def b64_pad(text):
    return text + "=" * ((4 - len(text) % 4) % 4)


def b64_urlsafe(text):
    raw = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")
    return raw.rstrip("=")


def b64_std(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def encode_subscription(links):
    return base64.b64encode(("\n".join(sorted(links)) + "\n").encode("utf-8")).decode("ascii")


def save_subscription(path, links):
    path = Path(path)
    path.write_text(encode_subscription(links) + "\n", encoding="utf-8")


def clean_link(link):
    return link.rstrip(".,;)]}")


def strip_quotes(value):
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        text = text[1:-1]
    return text.strip()


def first_value(obj, keys):
    if not isinstance(obj, dict):
        return ""
    lower = {str(k).lower(): v for k, v in obj.items()}
    for key in keys:
        value = lower.get(key.lower())
        if value is None:
            continue
        if isinstance(value, (str, int, float)) and str(value) != "":
            return str(value)
    return ""


def iter_values(obj):
    yield obj
    if isinstance(obj, dict):
        for value in obj.values():
            yield from iter_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_values(item)


def parse_json_maybe(text):
    if not isinstance(text, str):
        return None
    text = text.strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def decode_base64_maybe(text):
    if not isinstance(text, str):
        return ""
    candidate = text.strip()
    if len(candidate) < 16:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_+/=\-\s]+", candidate):
        return ""
    compact = re.sub(r"\s+", "", candidate)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(b64_pad(compact))
            decoded = raw.decode("utf-8")
        except Exception:
            continue
        markers = ("://", "{", "[", "proxies:", "server:", "password:", "port:")
        if any(marker in decoded for marker in markers):
            return decoded
    return ""


def split_endpoint(endpoint):
    endpoint = strip_quotes(endpoint)
    if not endpoint:
        return "", ""
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint.rsplit(":", 1)
        return host.strip("[]"), port
    if endpoint.count(":") == 1:
        return endpoint.rsplit(":", 1)
    return endpoint, ""


def build_link_from_dict(obj, source_name="Node"):
    if not isinstance(obj, dict):
        return ""

    proto = first_value(obj, ("type", "protocol", "server_type", "serverType", "mode", "network"))
    proto_l = proto.lower()
    name = first_value(obj, ("name", "remarks", "remark", "ps", "tag", "title", "server_name", "serverName", "server_n", "descri")) or source_name
    tag = urllib.parse.quote(name)

    host = first_value(
        obj,
        (
            "server",
            "host",
            "hostname",
            "address",
            "addr",
            "ip",
            "server_ip",
            "server_d",
            "server_domain",
            "server_addr",
            "server_address",
            "socks5_host",
            "socks5Host",
            "ss_host",
            "op_server",
            "op_domain",
            "vpn_server",
            "vpn_host",
            "remote",
        ),
    )
    port = first_value(
        obj,
        (
            "port",
            "server_port",
            "serverPort",
            "server_p",
            "socks5_port",
            "socks5Port",
            "ss_port",
            "op_port",
            "vpn_port",
            "remote_port",
        ),
    )
    endpoint = first_value(obj, ("endpoint", "Endpoint"))
    if endpoint and (not host or not port):
        endpoint_host, endpoint_port = split_endpoint(endpoint)
        host = host or endpoint_host
        port = port or endpoint_port

    password = first_value(
        obj,
        (
            "password",
            "pass",
            "passwd",
            "secret",
            "server_k",
            "key",
            "server_key",
            "ss_password",
            "socks5_password",
            "socks5Password",
            "op_password",
        ),
    )
    method = first_value(obj, ("cipher", "method", "encryption", "chiper", "ss_cipher", "ss_method")) or "aes-128-gcm"
    uuid = first_value(obj, ("uuid", "id", "user_id", "userId"))

    if not proto_l:
        if first_value(obj, ("cipher", "method", "encryption")) and password:
            proto_l = "ss"
        elif uuid and host and port:
            proto_l = "vmess"
        elif first_value(obj, ("obfs", "protocol_param", "obfs_param")):
            proto_l = "ssr"
        elif first_value(obj, ("ss_host", "ss_port", "ss_password")):
            proto_l = "ss"

    if first_value(obj, ("obfs", "protocol_param", "obfs_param")) and host and port and password:
        proto_l = "ssr"

    if ("ssr" in proto_l or proto_l == "shadowsocksr") and host and port and password:
        ssr_proto = first_value(obj, ("protocol", "protocol_type")) or "origin"
        obfs = first_value(obj, ("obfs", "obfs_type")) or "plain"
        pwd = b64_urlsafe(password)
        remarks = b64_urlsafe(name)
        group = b64_urlsafe(source_name)
        raw = f"{host}:{port}:{ssr_proto}:{method}:{obfs}:{pwd}/?remarks={remarks}&group={group}"
        return "ssr://" + b64_urlsafe(raw)

    if ("shadowsocks" in proto_l or proto_l == "ss") and host and port and password:
        userinfo = b64_urlsafe(f"{method}:{password}")
        return f"ss://{userinfo}@{host}:{port}#{tag}"

    if ("trojan" in proto_l) and host and port and password:
        sni = first_value(obj, ("sni", "server_name", "serverName", "peer", "host")) or host
        return f"trojan://{urllib.parse.quote(password)}@{host}:{port}?security=tls&type=tcp&sni={urllib.parse.quote(sni)}#{tag}"

    if ("vless" in proto_l) and host and port and uuid:
        security = first_value(obj, ("security",)) or ("tls" if first_value(obj, ("sni", "tls")) else "none")
        net = first_value(obj, ("net", "network", "transport")) or "tcp"
        sni = first_value(obj, ("sni", "server_name", "serverName")) or host
        return f"vless://{uuid}@{host}:{port}?security={security}&type={net}&sni={urllib.parse.quote(sni)}#{tag}"

    if ("vmess" in proto_l) and host and port and uuid:
        vmess = {
            "v": "2",
            "ps": name,
            "add": host,
            "port": str(port),
            "id": uuid,
            "aid": first_value(obj, ("alterId", "aid")) or "0",
            "scy": first_value(obj, ("scy", "cipher", "security")) or "auto",
            "net": first_value(obj, ("net", "network", "transport")) or "tcp",
            "type": first_value(obj, ("headerType", "header_type")) or "none",
            "host": first_value(obj, ("host", "ws_host")) or "",
            "path": first_value(obj, ("path", "ws_path")) or "",
            "tls": first_value(obj, ("tls", "security")) or "",
            "sni": first_value(obj, ("sni", "server_name", "serverName")) or "",
        }
        return "vmess://" + b64_std(json.dumps(vmess, ensure_ascii=False, separators=(",", ":")))

    if ("hysteria2" in proto_l or proto_l == "hy2" or "hysteria" in proto_l) and host and port and password:
        scheme = "hy2" if "2" in proto_l or proto_l == "hy2" else "hysteria"
        sni = first_value(obj, ("sni", "server_name", "serverName")) or host
        return f"{scheme}://{urllib.parse.quote(password)}@{host}:{port}?sni={urllib.parse.quote(sni)}#{tag}"

    if ("socks" in proto_l or proto_l == "s5") and host and port:
        username = first_value(obj, ("username", "user", "op_userName", "op_username", "socks5_username", "socks5Username"))
        auth = ""
        if username or password:
            auth = f"{urllib.parse.quote(username)}:{urllib.parse.quote(password)}@"
        return f"socks://{auth}{host}:{port}#{tag}"

    return ""


COUNTRY_NAME_ZH = {
    "US": "美国",
    "USA": "美国",
    "UNITED STATES": "美国",
    "UNITED STATES OF AMERICA": "美国",
    "UK": "英国",
    "GB": "英国",
    "GBR": "英国",
    "UNITED KINGDOM": "英国",
    "JP": "日本",
    "JPN": "日本",
    "JAPAN": "日本",
    "SG": "新加坡",
    "SGP": "新加坡",
    "SINGAPORE": "新加坡",
    "HK": "香港",
    "HKG": "香港",
    "HONG KONG": "香港",
    "TW": "台湾",
    "TWN": "台湾",
    "TAIWAN": "台湾",
    "KR": "韩国",
    "KOR": "韩国",
    "KOREA": "韩国",
    "SOUTH KOREA": "韩国",
    "CA": "加拿大",
    "CAN": "加拿大",
    "CANADA": "加拿大",
    "AU": "澳大利亚",
    "AUS": "澳大利亚",
    "AUSTRALIA": "澳大利亚",
    "DE": "德国",
    "DEU": "德国",
    "GERMANY": "德国",
    "FR": "法国",
    "FRA": "法国",
    "FRANCE": "法国",
    "NL": "荷兰",
    "NLD": "荷兰",
    "NETHERLANDS": "荷兰",
    "SE": "瑞典",
    "SWE": "瑞典",
    "SWEDEN": "瑞典",
    "CH": "瑞士",
    "CHE": "瑞士",
    "SWITZERLAND": "瑞士",
    "EE": "爱沙尼亚",
    "EST": "爱沙尼亚",
    "ESTONIA": "爱沙尼亚",
    "IT": "意大利",
    "ITA": "意大利",
    "ITALY": "意大利",
    "IN": "印度",
    "IND": "印度",
    "INDIA": "印度",
    "BR": "巴西",
    "BRA": "巴西",
    "BRAZIL": "巴西",
    "RU": "俄罗斯",
    "RUS": "俄罗斯",
    "RUSSIA": "俄罗斯",
    "TH": "泰国",
    "THA": "泰国",
    "THAILAND": "泰国",
    "VN": "越南",
    "VNM": "越南",
    "VIETNAM": "越南",
    "MY": "马来西亚",
    "MYS": "马来西亚",
    "MALAYSIA": "马来西亚",
    "ID": "印度尼西亚",
    "IDN": "印度尼西亚",
    "INDONESIA": "印度尼西亚",
    "PH": "菲律宾",
    "PHL": "菲律宾",
    "PHILIPPINES": "菲律宾",
    "ES": "西班牙",
    "ESP": "西班牙",
    "SPAIN": "西班牙",
    "TR": "土耳其",
    "TUR": "土耳其",
    "TURKEY": "土耳其",
    "PL": "波兰",
    "POL": "波兰",
    "POLAND": "波兰",
    "IE": "爱尔兰",
    "IRL": "爱尔兰",
    "IRELAND": "爱尔兰",
    "MX": "墨西哥",
    "MEX": "墨西哥",
    "MEXICO": "墨西哥",
    "AR": "阿根廷",
    "ARG": "阿根廷",
    "ARGENTINA": "阿根廷",
    "UA": "乌克兰",
    "UKR": "乌克兰",
    "UKRAINE": "乌克兰",
    "FI": "芬兰",
    "FIN": "芬兰",
    "FINLAND": "芬兰",
    "NO": "挪威",
    "NOR": "挪威",
    "NORWAY": "挪威",
    "DK": "丹麦",
    "DNK": "丹麦",
    "DENMARK": "丹麦",
    "BE": "比利时",
    "BEL": "比利时",
    "BELGIUM": "比利时",
    "AT": "奥地利",
    "AUT": "奥地利",
    "AUSTRIA": "奥地利",
    "PT": "葡萄牙",
    "PRT": "葡萄牙",
    "PORTUGAL": "葡萄牙",
    "IL": "以色列",
    "ISR": "以色列",
    "ISRAEL": "以色列",
    "AE": "阿联酋",
    "ARE": "阿联酋",
    "UAE": "阿联酋",
    "UNITED ARAB EMIRATES": "阿联酋",
}


def country_name_zh(value, default="未知"):
    text = str(value or "").strip()
    if not text:
        return default
    normalized = re.sub(r"[_-]+", " ", text).strip().upper()
    return COUNTRY_NAME_ZH.get(normalized, text)


def localize_country_names(text):
    result = str(text or "")
    if not result:
        return result

    items = sorted(COUNTRY_NAME_ZH.items(), key=lambda kv: len(kv[0]), reverse=True)
    for key, zh in items:
        if len(key) <= 3:
            pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(key)}(?![A-Za-z0-9])", re.IGNORECASE)
        else:
            pattern = re.compile(rf"\b{re.escape(key)}\b", re.IGNORECASE)
        result = pattern.sub(zh, result)
    for zh in sorted(set(COUNTRY_NAME_ZH.values()), key=len, reverse=True):
        result = re.sub(
            rf"{re.escape(zh)}([\s/_|,，()（）-]+){re.escape(zh)}(?=$|[\s/_|,，()（）-])",
            zh,
            result,
        )
    return result


def localize_link_name(link):
    if not isinstance(link, str):
        return link

    if link.startswith("vmess://"):
        try:
            payload = link[8:]
            data = json.loads(base64.b64decode(b64_pad(payload)).decode("utf-8"))
            if isinstance(data, dict) and data.get("ps"):
                data["ps"] = localize_country_names(data["ps"])
                return "vmess://" + b64_std(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            return link

    if link.startswith("ssr://"):
        try:
            payload = link[6:]
            decoded = base64.urlsafe_b64decode(b64_pad(payload)).decode("utf-8")
            base, sep, query = decoded.partition("/?")
            if sep:
                params = urllib.parse.parse_qs(query, keep_blank_values=True)
                remarks = params.get("remarks", [""])[0]
                if remarks:
                    raw_name = base64.urlsafe_b64decode(b64_pad(remarks)).decode("utf-8")
                    new_name = localize_country_names(raw_name)
                    params["remarks"] = [b64_urlsafe(new_name)]
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    return "ssr://" + b64_urlsafe(f"{base}/?{new_query}")
        except Exception:
            return link

    if "://" in link and "#" in link:
        base, tag = link.rsplit("#", 1)
        name = urllib.parse.unquote(tag)
        localized = localize_country_names(name)
        if localized != name:
            return f"{base}#{urllib.parse.quote(localized)}"

    return link


def localize_link_names(links):
    return [localize_link_name(link) for link in links]


def _first_list_item(value):
    if isinstance(value, list) and value:
        return value[0]
    return None


def _query_from_pairs(pairs):
    return urllib.parse.urlencode(
        {key: value for key, value in pairs.items() if value not in (None, "")},
        doseq=True,
    )


def _build_vmess_from_outbound(outbound, source_name):
    settings = outbound.get("settings") if isinstance(outbound, dict) else None
    stream = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    if not isinstance(settings, dict):
        return ""

    vnext = _first_list_item(settings.get("vnext"))
    if not isinstance(vnext, dict):
        return ""
    user = _first_list_item(vnext.get("users"))
    if not isinstance(user, dict):
        return ""

    host = first_value(vnext, ("address", "host", "server"))
    port = first_value(vnext, ("port",))
    uuid = first_value(user, ("id", "uuid"))
    if not host or not port or not uuid:
        return ""

    net = ""
    security = ""
    ws_host = ""
    path = ""
    header_type = "none"
    sni = ""
    if isinstance(stream, dict):
        net = first_value(stream, ("network",)) or "tcp"
        security = first_value(stream, ("security",))
        tcp_settings = stream.get("tcpSettings")
        if isinstance(tcp_settings, dict):
            header = tcp_settings.get("header")
            if isinstance(header, dict):
                header_type = first_value(header, ("type",)) or "none"
        ws_settings = stream.get("wsSettings")
        if isinstance(ws_settings, dict):
            path = first_value(ws_settings, ("path",))
            headers = ws_settings.get("headers")
            if isinstance(headers, dict):
                ws_host = first_value(headers, ("Host", "host"))
        tls_settings = stream.get("tlsSettings")
        if isinstance(tls_settings, dict):
            sni = first_value(tls_settings, ("serverName", "server_name", "sni"))

    name = first_value(outbound, ("tag", "remarks", "name", "ps")) or f"{source_name}-{host}"
    vmess = {
        "v": "2",
        "ps": name,
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": first_value(user, ("alterId", "aid")) or "0",
        "scy": first_value(user, ("security", "cipher")) or "auto",
        "net": net or "tcp",
        "type": header_type,
        "host": ws_host,
        "path": path,
        "tls": security,
        "sni": sni,
    }
    return "vmess://" + b64_std(json.dumps(vmess, ensure_ascii=False, separators=(",", ":")))


def _build_vless_from_outbound(outbound, source_name):
    settings = outbound.get("settings") if isinstance(outbound, dict) else None
    stream = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    if not isinstance(settings, dict):
        return ""

    vnext = _first_list_item(settings.get("vnext"))
    if not isinstance(vnext, dict):
        return ""
    user = _first_list_item(vnext.get("users"))
    if not isinstance(user, dict):
        return ""

    host = first_value(vnext, ("address", "host", "server"))
    port = first_value(vnext, ("port",))
    uuid = first_value(user, ("id", "uuid"))
    if not host or not port or not uuid:
        return ""

    net = "tcp"
    security = "none"
    flow = first_value(user, ("flow",))
    sni = ""
    path = ""
    ws_host = ""
    if isinstance(stream, dict):
        net = first_value(stream, ("network",)) or net
        security = first_value(stream, ("security",)) or security
        ws_settings = stream.get("wsSettings")
        if isinstance(ws_settings, dict):
            path = first_value(ws_settings, ("path",))
            headers = ws_settings.get("headers")
            if isinstance(headers, dict):
                ws_host = first_value(headers, ("Host", "host"))
        tls_settings = stream.get("tlsSettings")
        if isinstance(tls_settings, dict):
            sni = first_value(tls_settings, ("serverName", "server_name", "sni"))

    name = first_value(outbound, ("tag", "remarks", "name", "ps")) or f"{source_name}-{host}"
    query = _query_from_pairs(
        {
            "security": security,
            "type": net,
            "flow": flow,
            "sni": sni,
            "host": ws_host,
            "path": path,
        }
    )
    return f"vless://{uuid}@{host}:{port}?{query}#{urllib.parse.quote(name)}"


def _build_trojan_from_outbound(outbound, source_name):
    settings = outbound.get("settings") if isinstance(outbound, dict) else None
    stream = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    if not isinstance(settings, dict):
        return ""

    server = _first_list_item(settings.get("servers"))
    if not isinstance(server, dict):
        return ""

    host = first_value(server, ("address", "host", "server"))
    port = first_value(server, ("port",))
    password = first_value(server, ("password", "pass"))
    if not host or not port or not password:
        return ""

    net = "tcp"
    security = "tls"
    sni = host
    if isinstance(stream, dict):
        net = first_value(stream, ("network",)) or net
        security = first_value(stream, ("security",)) or security
        tls_settings = stream.get("tlsSettings")
        if isinstance(tls_settings, dict):
            sni = first_value(tls_settings, ("serverName", "server_name", "sni")) or sni

    name = first_value(outbound, ("tag", "remarks", "name", "ps")) or f"{source_name}-{host}"
    query = _query_from_pairs({"security": security, "type": net, "sni": sni})
    return f"trojan://{urllib.parse.quote(password)}@{host}:{port}?{query}#{urllib.parse.quote(name)}"


def _build_shadowsocks_from_outbound(outbound, source_name):
    settings = outbound.get("settings") if isinstance(outbound, dict) else None
    if not isinstance(settings, dict):
        return ""

    server = _first_list_item(settings.get("servers"))
    if not isinstance(server, dict):
        return ""

    host = first_value(server, ("address", "host", "server"))
    port = first_value(server, ("port",))
    password = first_value(server, ("password", "pass"))
    method = first_value(server, ("method", "cipher", "security")) or "aes-128-gcm"
    if not host or not port or not password:
        return ""

    name = first_value(outbound, ("tag", "remarks", "name", "ps")) or f"{source_name}-{host}"
    userinfo = b64_urlsafe(f"{method}:{password}")
    return f"ss://{userinfo}@{host}:{port}#{urllib.parse.quote(name)}"


def build_links_from_v2ray_config(obj, source_name="Node"):
    if not isinstance(obj, dict):
        return set()

    outbounds = obj.get("outbounds")
    if not isinstance(outbounds, list):
        outbound = obj.get("outbound")
        outbounds = [outbound] if isinstance(outbound, dict) else []

    links = set()
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        proto = first_value(outbound, ("protocol",)).lower()
        link = ""
        if proto == "vmess":
            link = _build_vmess_from_outbound(outbound, source_name)
        elif proto == "vless":
            link = _build_vless_from_outbound(outbound, source_name)
        elif proto == "trojan":
            link = _build_trojan_from_outbound(outbound, source_name)
        elif proto in {"shadowsocks", "ss"}:
            link = _build_shadowsocks_from_outbound(outbound, source_name)
        if link:
            links.add(link)
    return links


def parse_inline_map(text):
    text = text.strip()
    if text.startswith("-"):
        text = text[1:].strip()
    if text.startswith("{") and text.endswith("}"):
        text = text[1:-1]
    result = {}
    parts = re.split(r",\s*(?=[A-Za-z0-9_-]+\s*:)", text)
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        result[strip_quotes(key)] = strip_quotes(value)
    return result


def parse_clash_like(text):
    records = []
    current = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^-\s*\{.*\}\s*$", stripped):
            records.append(parse_inline_map(stripped))
            current = None
            continue
        if re.match(r"^-\s+name\s*:", stripped):
            if current:
                records.append(current)
            current = parse_inline_map(stripped[1:].strip())
            continue
        if current is not None and ":" in stripped:
            key, value = stripped.split(":", 1)
            key = strip_quotes(key)
            if key and not key.startswith("-"):
                current[key] = strip_quotes(value)
    if current:
        records.append(current)
    return records


def parse_proxy_conf(text):
    records = []
    in_proxy = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_proxy = line.lower() == "[proxy]"
            continue
        if not in_proxy or "=" not in line:
            continue

        name, body = line.split("=", 1)
        name = strip_quotes(name)
        parts = [strip_quotes(part) for part in body.split(",")]
        if len(parts) < 3:
            continue
        proto = parts[0].lower()
        if proto in {"direct", "reject", "block"}:
            continue

        record = {
            "name": name,
            "type": proto,
            "server": parts[1],
            "port": parts[2],
        }
        for item in parts[3:]:
            if "=" in item:
                key, value = item.split("=", 1)
                record[strip_quotes(key)] = strip_quotes(value)
                continue
            if proto in {"ss", "shadowsocks"} and "method" not in record:
                record["method"] = item
            elif proto in {"ss", "shadowsocks"} and "password" not in record:
                record["password"] = item
            elif proto == "trojan" and "password" not in record:
                record["password"] = item
            elif proto in {"vmess", "vless"} and "uuid" not in record:
                record["uuid"] = item
        records.append(record)
    return records


def extract_links(obj, source_name="Node", _depth=0):
    if _depth > 6:
        return set()

    links = set()
    if isinstance(obj, str):
        for match in LINK_RE.findall(obj):
            links.add(clean_link(match))

        parsed = parse_json_maybe(obj)
        if parsed is not None:
            links.update(extract_links(parsed, source_name, _depth + 1))

        decoded = decode_base64_maybe(obj)
        if decoded and decoded != obj:
            links.update(extract_links(decoded, source_name, _depth + 1))

        for record in parse_clash_like(obj):
            link = build_link_from_dict(record, source_name)
            if link:
                links.add(link)
        for record in parse_proxy_conf(obj):
            link = build_link_from_dict(record, source_name)
            if link:
                links.add(link)
        return links

    if isinstance(obj, dict):
        links.update(build_links_from_v2ray_config(obj, source_name))
        link = build_link_from_dict(obj, source_name)
        if link:
            links.add(link)
        for value in obj.values():
            links.update(extract_links(value, source_name, _depth + 1))
        return links

    if isinstance(obj, list):
        for item in obj:
            links.update(extract_links(item, source_name, _depth + 1))
        return links

    return links


try:
    from _country_names import (
        country_name_zh,
        localize_country_names,
        localize_link_name,
        localize_link_names,
    )
except Exception:
    pass
