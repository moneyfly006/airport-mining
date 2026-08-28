/**
 * Cloudflare Email Worker — 无限邮箱接收端
 *
 * 配套文章方案（tech-shrimp《白嫖Cloudflare无限多企业邮箱》）：
 *   1. 域名托管到 Cloudflare，启用 Email Routing
 *   2. catch-all 路由规则指向本 Worker（action: worker）
 *   3. 本 Worker 收到任何 前缀@你的域名 的邮件后存入 KV
 *   4. 通过 HTTP API 读取邮件 → 程序化提取验证码
 *
 * 从而获得“无限个邮箱”（无需预创建，任意前缀即收件箱）。
 *
 * 部署方式：由 scripts/_cf_mail.py 通过 CF API 自动上传并绑定 KV。
 *
 * KV 结构：
 *   key  = "inbox:" + 收件人邮箱（小写）
 *   value = JSON 数组，每封邮件 {id, from, to, subject, date, text, html}
 *
 * HTTP API（需 Authorization: Bearer AUTH_TOKEN）：
 *   GET    /api/inbox?email=xxx@domain      → 该邮箱邮件列表
 *   DELETE /api/inbox?email=xxx@domain      → 清空该邮箱收件箱
 *   GET    /api/health                      → 健康检查
 */

const MAX_STORED = 20; // 每邮箱最多保留的邮件数
const MAX_BODY = 20000; // 单封邮件正文截断字节数
const MAX_RAW = 50000; // 原始 MIME 截断字节数（Python 端标准库解析用）

export default {
  /**
   * 邮件处理入口：Email Routing 把邮件投递到这里。
   */
  async email(message, env, ctx) {
    const to = String(message.to || "").toLowerCase().trim();
    if (!to) {
      // 无法判断收件箱，静默丢弃
      return;
    }

    let parsed = { subject: "", text: "", html: "", from: "", date: "", raw: "" };
    try {
      // message.raw 是 ReadableStream，先读成字符串（原始 MIME）
      const raw = await new Response(message.raw).text();
      parsed = parseMime(raw, message.headers);
      // 保存原始 MIME，Python 端用标准库 email 精确解析验证码
      parsed.raw = raw.slice(0, MAX_RAW);
    } catch (err) {
      parsed = { subject: "", text: "", html: "", from: "", date: "", raw: "" };
    }

    const mail = {
      id: (message.headers && message.headers.get("message-id")) || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      from: parsed.from,
      to,
      subject: parsed.subject,
      date: parsed.date,
      text: parsed.text.slice(0, MAX_BODY),
      html: parsed.html.slice(0, MAX_BODY),
      raw: parsed.raw,
    };

    const key = "inbox:" + to;
    let list = [];
    try {
      const prev = await env.MAILBOX.get(key, "json");
      if (Array.isArray(prev)) list = prev;
    } catch (_) {
      list = [];
    }
    list.unshift(mail);
    if (list.length > MAX_STORED) list.length = MAX_STORED;
    try {
      await env.MAILBOX.put(key, JSON.stringify(list), { expirationTtl: 60 * 60 * 24 * 7 });
    } catch (_) {
      // KV 写入失败不阻塞邮件投递
    }
  },

  /**
   * HTTP 入口：程序化读信 API。
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 健康检查无需鉴权
    if (url.pathname === "/api/health") {
      return json({ ok: true, worker: "cf-email-worker" });
    }

    // 鉴权
    const auth = request.headers.get("Authorization") || "";
    const expected = "Bearer " + (env.AUTH_TOKEN || "");
    if (!expected || auth !== expected) {
      return json({ error: "unauthorized" }, 401);
    }

    if (url.pathname !== "/api/inbox") {
      return json({ error: "not found" }, 404);
    }
    const email = (url.searchParams.get("email") || "").toLowerCase().trim();
    if (!email || !email.includes("@")) {
      return json({ error: "email query param required" }, 400);
    }
    const key = "inbox:" + email;

    if (request.method === "GET") {
      let list = [];
      try {
        const prev = await env.MAILBOX.get(key, "json");
        if (Array.isArray(prev)) list = prev;
      } catch (_) {
        list = [];
      }
      return json({ email, count: list.length, mails: list });
    }

    if (request.method === "DELETE") {
      await env.MAILBOX.delete(key);
      return json({ email, deleted: true });
    }

    return json({ error: "method not allowed" }, 405);  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

/**
 * 极简 MIME 解析：提取 subject / from / date / 纯文本正文 / HTML 正文。
 * 支持 multipart/alternative 与 base64 / quoted-printable 传输编码。
 */
function parseMime(raw, headers) {
  const result = { subject: "", text: "", html: "", from: "", date: "" };
  try {
    if (headers) {
      result.subject = decodeHeader(headers.get("subject") || "");
      result.from = decodeHeader(headers.get("from") || "");
      result.date = headers.get("date") || "";
    }
    // 完整原始内容交给 collectBody（multipart boundary 声明在头部）
    collectBody(raw, result);
  } catch (_) {
    // 解析失败保留头部信息
  }
  return result;
}

function collectBody(raw, result, depth = 0) {
  if (depth > 8) return;
  const boundaryMatch = raw.match(/boundary="?([^";\r\n]+)"?/i);
  const contentTypeMatch = raw.match(/Content-Type:\s*([^;\r\n]+)/i);

  if (boundaryMatch && contentTypeMatch && /multipart/i.test(contentTypeMatch[1])) {
    const boundary = boundaryMatch[1];
    const parts = raw.split("--" + boundary);
    for (const part of parts) {
      const p = part.replace(/^\r?\n/, "");
      if (p.trim() === "" || p.startsWith("--")) continue;
      collectBody(p, result, depth + 1);
    }
    return;
  }

  // 单段：解析传输编码
  const encMatch = raw.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
  const cte = encMatch ? encMatch[1].trim().toLowerCase() : "";
  const bodyStart = raw.indexOf("\r\n\r\n");
  const content = bodyStart >= 0 ? raw.slice(bodyStart + 4) : raw;

  let decoded = content;
  if (cte === "base64") {
    try {
      decoded = decodeBase64Text(content);
    } catch (_) {
      decoded = content;
    }
  } else if (cte === "quoted-printable") {
    decoded = decodeQuotedPrintable(content);
  }

  if (contentTypeMatch && /text\/html/i.test(contentTypeMatch[1])) {
    result.html += decoded + "\n";
  } else {
    result.text += decoded + "\n";
  }
}

/** base64 文本解码：atob 返回 binary string，需转 Uint8Array 再 UTF-8 解码 */
function decodeBase64Text(s) {
  const bin = atob(s.replace(/\s+/g, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8").decode(bytes);
}

function decodeQuotedPrintable(s) {
  try {
    const cleaned = s.replace(/=\r?\n/g, "");
    const bytes = [];
    for (let i = 0; i < cleaned.length; i++) {
      if (cleaned[i] === "=" && i + 2 < cleaned.length) {
        bytes.push(parseInt(cleaned.slice(i + 1, i + 3), 16));
        i += 2;
      } else {
        bytes.push(cleaned.charCodeAt(i) & 0xff);
      }
    }
    return new TextDecoder("utf-8").decode(new Uint8Array(bytes));
  } catch (_) {
    return s;
  }
}

/** RFC 2047 编码头解码（=?UTF-8?B?...?= / =?UTF-8?Q?...?=） */
function decodeHeader(value) {
  if (!value) return "";
  const re = /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g;
  let out = "";
  let last = 0;
  let m;
  let matched = false;
  while ((m = re.exec(value)) !== null) {
    matched = true;
    out += value.slice(last, m.index);
    try {
      if (m[2].toUpperCase() === "B") {
        out += decodeBase64Text(m[3]);
      } else {
        out += m[3].replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
      }
    } catch (_) {
      out += m[3];
    }
    last = re.lastIndex;
  }
  return matched ? out + value.slice(last) : value;
}
