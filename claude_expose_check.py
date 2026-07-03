#!/usr/bin/env python3
"""Claude Code 暴露自检（standalone，独立于 ipcheck 主程序）。

检测本机使用 Claude Code 时的四类暴露风险，全部为本地静态判断，不联网、不加依赖：
  1. 反蒸馏水印：你的请求会不会被打指纹、打成 8 态里的哪一种
  2. 敏感信息暴露：走非官方端点时，system prompt 里哪些字段会过第三方
  3. 遥测状态：复刻 VAs() 三级判定，报你当前是哪一档
  4. 文本反向检测：给一段文本，反解里面藏没藏水印

名单与逻辑默认从本机 Claude Code 二进制「实时解码」（按解码器指纹定位，跨版本不失效），
解码失败时回退到内置快照（可能过期，会提示）。

用法：
  python claude_expose_check.py                    # 全量文字报告 + 可视化报告图
  python claude_expose_check.py --text             # 仅终端文字，不生成图
  python claude_expose_check.py --show             # 文字报告 + 图，并在窗口预览
  python claude_expose_check.py --output x.png     # 指定报告图输出路径
  python3 claude_expose_check.py --scan-file x   # 检测某文件文本里的水印
  echo "..." | python3 claude_expose_check.py --scan-stdin
  python3 claude_expose_check.py --binary <path> # 手动指定二进制

可视化依赖：pip install matplotlib（未安装时自动回退为 SVG）

诚实边界：这是基于本地「配置 + 二进制逻辑」的静态判断，只说明「按你的配置会发生什么」，
不代表实际发出的字节。要 100% 坐实需要抓包（mitmproxy 等）。
"""

# ── 状态备注（2026-07-01）─────────────────────────────────────────────────
# 反蒸馏水印已在 Claude Code 2.1.198 从二进制移除：「反蒸馏水印自检」与「文本反向
# 检测」两块基本失效，仅留作历史参照。
# 本文件暂不删除、也不并入 ipcheck 主面板，主要为保留这三块之后可能有用的逻辑
# （面板目前不含）：
#   · 敏感信息暴露（system prompt 会携带哪些字段过第三方）
#   · 遥测状态（复刻 VAs() 三级开关判定）
#   · 服务端可见参数（--server-params：账号 UUID / 请求头 / metadata.user_id 等，
#     「删了客户端水印也删不掉」的识别信息）
# 之后要用时，再决定这三块是搬进面板还是保留独立脚本。
# ──────────────────────────────────────────────────────────────────────────

import os
import re
import sys
import json
import base64
import argparse
from urllib.parse import urlsplit


def _win_utf8_console():
    """Windows 控制台切换为 UTF-8 代码页 (65001)，避免中文/符号乱码。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)
        kernel32.SetConsoleCP(65001)
    except Exception:
        pass


def _ensure_utf8_stdio():
    """强制 stdout/stderr 使用 UTF-8，避免 Windows GBK 终端输出 emoji/中文时崩溃。"""
    _win_utf8_console()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def out(*args, **kwargs):
    """统一终端输出；优先 UTF-8 字节写入，减少 Windows 下问号/乱码。"""
    if kwargs:
        file = kwargs.get("file", sys.stdout)
        if file is not sys.stdout and file is not sys.stderr:
            print(*args, **kwargs)
            return
    sep = kwargs.get("sep", " ")
    end = kwargs.get("end", "\n")
    file = kwargs.get("file", sys.stdout)
    text = sep.join(str(a) for a in args) + end
    try:
        file.write(text)
        file.flush()
    except (UnicodeEncodeError, AttributeError):
        buf = getattr(file, "buffer", None)
        if buf is not None:
            buf.write(text.encode("utf-8", errors="replace"))
            buf.flush()
        else:
            print(*args, **kwargs)


def _safe_print(*args, **kwargs):
    """兼容旧调用，转发到 out。"""
    out(*args, **kwargs)


# ---------- 颜色 ----------
_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()


class C:
    R = "" if _NO_COLOR else "\033[31m"
    G = "" if _NO_COLOR else "\033[32m"
    Y = "" if _NO_COLOR else "\033[33m"
    B = "" if _NO_COLOR else "\033[36m"
    DIM = "" if _NO_COLOR else "\033[2m"
    BOLD = "" if _NO_COLOR else "\033[1m"
    X = "" if _NO_COLOR else "\033[0m"


def ok(s):
    return f"{C.G}{s}{C.X}"


def warn(s):
    return f"{C.Y}{s}{C.X}"


def bad(s):
    return f"{C.R}{s}{C.X}"


def head(s):
    _safe_print(f"\n{C.BOLD}{s}{C.X}")


# ---------- 撇号常量（edp 的四个返回值）----------
APOS = {
    (False, False): ("'", "U+0027", "APOSTROPHE"),
    (True, False): ("’", "U+2019", "RIGHT SINGLE QUOTATION MARK"),
    (False, True): ("ʼ", "U+02BC", "MODIFIER LETTER APOSTROPHE"),
    (True, True): ("ʹ", "U+02B9", "MODIFIER LETTER PRIME"),
}
# 反查：码位 -> (known, labKw)
CP_TO_FLAGS = {"’": (True, False), "ʼ": (False, True), "ʹ": (True, True)}

CN_TZ = {"Asia/Shanghai", "Asia/Urumqi"}

# 内置快照（回退用，来自 2.1.196/197 解码，跨版本一致）。若从二进制解码成功则不使用。
FALLBACK_KEYWORDS = [
    "deepseek", "moonshot", "minimax", "xaminim", "zhipu", "bigmodel",
    "baichuan", "stepfun", "01ai", "dashscope", "volces",
]

# 11 关键词 → 公司（去重后 9 家）
KW_COMPANY = {
    "deepseek": "深度求索 DeepSeek（V3 / R1）",
    "moonshot": "月之暗面 Moonshot（Kimi）",
    "minimax": "MiniMax 稀宇（海螺）",
    "xaminim": "MiniMax（minimax 反拼域名）",
    "zhipu": "智谱 Zhipu（GLM）",
    "bigmodel": "智谱（开放平台 bigmodel.cn）",
    "baichuan": "百川智能 Baichuan",
    "stepfun": "阶跃星辰 StepFun（跃问）",
    "01ai": "零一万物 01.AI（Yi）",
    "dashscope": "阿里云 通义千问 DashScope",
    "volces": "火山引擎 / 字节 豆包",
}


# ---------- 定位 Claude Code 二进制 ----------
def _ver_key(name):
    parts = re.findall(r"\d+", name)
    return tuple(int(p) for p in parts) if parts else (0,)


def find_binary(override=None):
    if override:
        return override if os.path.exists(override) else None
    base = os.path.expanduser("~/.local/share/claude/versions")
    if os.path.isdir(base):
        vers = [d for d in os.listdir(base) if os.path.isfile(os.path.join(base, d))]
        if vers:
            newest = sorted(vers, key=_ver_key)[-1]
            return os.path.join(base, newest)
    # 兜底：解析 which claude 的软链
    for cand in ("claude",):
        path = _which(cand)
        if path:
            real = os.path.realpath(path)
            if os.path.exists(real):
                return real
    return None


def _which(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


# ---------- 从二进制解码 147 域名 + 11 关键词（指纹定位，跨版本）----------
def decode_lists(binary_path, text=None):
    """返回 (domains, keywords, meta)。失败返回 (None, None, err)。"""
    if text is None:
        try:
            text = open(binary_path, "rb").read().decode("latin-1")
        except Exception as e:
            return None, None, f"读取二进制失败: {e}"

    # 解码器指纹：function X(e){...String.fromCharCode(r^CONST);return n.split(",")}
    mdec = re.search(
        r'function (\w+)\(e\)\{let t=Buffer\.from\(e,"base64"\),n="";'
        r'for\(let r of t\)n\+=String\.fromCharCode\(r\^(\w+)\);return n\.split\(","\)\}',
        text,
    )
    if not mdec:
        return None, None, "未定位到解码器（二进制结构可能已变）"
    decoder, const_name = mdec.group(1), mdec.group(2)

    mconst = re.search(r"\b" + re.escape(const_name) + r"=(\d+)", text)
    if not mconst:
        return None, None, "未定位到 XOR 常量"
    xor = int(mconst.group(1))

    # 惰性解码赋值：A=vn(()=>DECODER(BLOB))
    assigns = re.findall(
        r"(\w+)=\w+\(\(\)=>" + re.escape(decoder) + r"\((\w+)\)\)", text
    )
    lists = []
    for _name, blob_var in assigns:
        mb = re.search(r"\b" + re.escape(blob_var) + r'="([^"]+)"', text)
        if not mb:
            continue
        b = mb.group(1)
        try:
            data = base64.b64decode(b + "=" * (-len(b) % 4))
            items = "".join(chr(x ^ xor) for x in data).split(",")
            lists.append(items)
        except Exception:
            continue

    domains = keywords = None
    for lst in lists:
        if "cn" in lst or len(lst) > 40:
            domains = lst
        else:
            keywords = lst
    if domains is None and lists:
        domains = max(lists, key=len)
    if keywords is None and len(lists) >= 2:
        keywords = min(lists, key=len)

    if domains is None:
        return None, None, "解码器定位到了，但没解出域名表"
    meta = f"XOR={xor}, 解码器={decoder}(), 域名 {len(domains)} 项, 关键词 {len(keywords) if keywords else 0} 项"
    return domains, keywords, meta


def binary_watermark_status(binary_path):
    """判断二进制里水印在不在。返回 dict：
    status = present / removed / obfuscation-changed / read-error / no-binary
    """
    version = os.path.basename(binary_path) if binary_path else None
    if not binary_path:
        return {"status": "no-binary", "version": None, "meta": "未找到 Claude Code 二进制",
                "domains": None, "keywords": None}
    try:
        text = open(binary_path, "rb").read().decode("latin-1")
    except Exception as e:
        return {"status": "read-error", "version": version, "meta": str(e),
                "domains": None, "keywords": None}

    # 水印三个独立特征：时区判断代码 / 撇号表 / XOR 解码器
    sig_tz = bool(re.search(r'==="Asia/Shanghai"', text))
    sig_apos = ("\\u02B9" in text) or ("ʹ" in text)
    sig_dec = bool(re.search(r'String\.fromCharCode\(\w\^\w+\);return \w+\.split\(","\)', text))
    if not (sig_tz or sig_apos or sig_dec):
        return {"status": "removed", "version": version,
                "meta": "无时区判断 / 撇号表 / XOR 解码器特征", "domains": None, "keywords": None}

    domains, keywords, meta = decode_lists(binary_path, text=text)
    if domains is None:
        return {"status": "obfuscation-changed", "version": version, "meta": meta,
                "domains": None, "keywords": None}
    return {"status": "present", "version": version, "meta": meta,
            "domains": domains, "keywords": keywords}


# ---------- 读取 ANTHROPIC_BASE_URL（shell env + settings.json）----------
def settings_paths():
    cfgdir = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return [
        os.path.join(cfgdir, "settings.json"),
        os.path.join(cfgdir, "settings.local.json"),
    ]


def read_settings_env():
    """合并读取 settings.json 的 env 块。"""
    merged = {}
    for p in settings_paths():
        if os.path.exists(p):
            try:
                d = json.load(open(p))
                for k, v in (d.get("env") or {}).items():
                    merged.setdefault(k, v)
            except Exception:
                pass
    return merged


def get_base_url():
    """返回 (effective_url, source, all_sources)。"""
    shell = os.environ.get("ANTHROPIC_BASE_URL")
    sett = read_settings_env().get("ANTHROPIC_BASE_URL")
    if shell:
        return shell, "shell 环境变量", {"shell": shell, "settings.json": sett}
    if sett:
        return sett, "settings.json", {"shell": None, "settings.json": sett}
    return None, None, {"shell": None, "settings.json": None}


# ---------- 时区（IANA 名，faithful to Intl.timeZone）----------
def get_iana_tz():
    """读取本机 IANA 时区名，兼容 macOS / Linux / Windows。"""
    tz = os.environ.get("TZ")
    if tz and "/" in tz:
        return tz
    p = "/etc/localtime"
    if os.path.islink(p):
        target = os.readlink(p)
        if "zoneinfo/" in target:
            return target.split("zoneinfo/", 1)[1]
    if os.path.exists("/etc/timezone"):
        try:
            return open("/etc/timezone").read().strip()
        except Exception:
            pass
    try:
        from datetime import datetime

        tzinfo = datetime.now().astimezone().tzinfo
        if tzinfo and hasattr(tzinfo, "key"):
            return tzinfo.key
    except Exception:
        pass
    return None


# ---------- 复刻 Crt / Qup / Zup 判定 ----------
def js_host(url):
    """模拟 JS new URL(e).host（含端口，不含 userinfo）。"""
    try:
        sp = urlsplit(url)
        host = sp.hostname or ""
        if sp.port:
            host = f"{host}:{sp.port}"
        return host.lower()
    except Exception:
        return None


def js_hostname(url):
    """模拟 JS new URL(e).hostname（不含端口）。"""
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except Exception:
        return None


def is_official(base_url):
    # Crt(): 未设 → true；否则 Rrt() 判 host === "api.anthropic.com"
    if not base_url:
        return True
    return js_host(base_url) == "api.anthropic.com"


def classify(host, domains, keywords, tz):
    known = any(host == d or host.endswith("." + d) for d in domains) if host else False
    labKw = any(k in host for k in keywords) if (host and keywords) else False
    cnTZ = tz in CN_TZ
    return known, labKw, cnTZ


# ---------- 结构化采集（供可视化报告使用）----------
def gather_watermark(base_url, domains, keywords, tz, status="present"):
    """采集水印模块结论，返回 dict。"""
    official = is_official(base_url)
    host = js_hostname(base_url) if base_url else None
    known = lab_kw = cn_tz = marked = False
    apos_char = date_sep = summary = ""
    level = "safe"

    if status == "removed":
        summary = "客户端水印已移除（2.1.198+）"
        level = "safe"
    elif official:
        summary = "官方直连，客户端水印不触发"
        level = "safe"
    else:
        known, lab_kw, cn_tz = classify(host, domains, keywords, tz)
        marked = known or lab_kw or cn_tz
        ch, cp, _ = APOS[(known, lab_kw)]
        date_sep = "/" if cn_tz else "-"
        apos_char = cp
        if marked:
            summary = f"非官方端点 + 可识别指纹（撇号 {cp}，日期 {date_sep}）"
            level = "danger"
        else:
            summary = "非官方端点，但撇号/日期与官方基线不可区分"
            level = "warn"

    return {
        "status": status,
        "official": official,
        "base_url": base_url,
        "host": host,
        "tz": tz,
        "known": known,
        "lab_kw": lab_kw,
        "cn_tz": cn_tz,
        "marked": marked,
        "apos_char": apos_char,
        "date_sep": date_sep,
        "summary": summary,
        "level": level,
    }


def gather_exposure(base_url):
    """采集敏感信息暴露模块结论，返回 dict。"""
    official = is_official(base_url)
    cwd = os.getcwd()
    in_git = os.path.isdir(os.path.join(cwd, ".git")) or _has_git_parent(cwd)
    claudemd = None
    for cand in (os.path.join(cwd, "CLAUDE.md"), os.path.expanduser("~/.claude/CLAUDE.md")):
        if os.path.exists(cand):
            claudemd = cand
            break
    email = _read_oauth_email()
    fields = [
        {"label": "工作目录路径", "value": cwd, "risk": 5, "note": "含用户名与项目结构"},
        {"label": "Git 仓库", "value": "是" if in_git else "否", "risk": 4 if in_git else 1, "note": "会带改动文件名"},
        {"label": "CLAUDE.md", "value": "有" if claudemd else "无", "risk": 4 if claudemd else 0, "note": "项目规范全文"},
        {"label": "邮箱", "value": mask_email(email) if email else "未读到", "risk": 3 if email else 0, "note": ""},
        {"label": "系统信息", "value": "OS / 平台 / Shell", "risk": 2, "note": ""},
    ]
    if official:
        flow = "官方 Anthropic，字段仅发往官方"
        level = "safe"
    else:
        flow = f"非官方端点 → 以上字段全部经过 {js_hostname(base_url) or '第三方'}"
        level = "danger"
    return {"official": official, "fields": fields, "flow": flow, "level": level}


def gather_telemetry():
    """采集遥测档位，返回 dict。"""
    env = dict(os.environ)
    sett = read_settings_env()

    def getv(key):
        return env.get(key) or sett.get(key)

    ness = getv("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
    tele = getv("DISABLE_TELEMETRY")
    err = getv("DISABLE_ERROR_REPORTING")
    dnt = getv("DO_NOT_TRACK")

    if ness:
        level, label, desc = "safe", "essential-traffic", "最严：只留必要推理请求"
    elif tele:
        level, label, desc = "warn", "no-telemetry", "运营指标关，Sentry 等可能仍在"
    elif dnt:
        level, label, desc = "warn", "do-not-track", "遵循 DNT，部分关闭"
    else:
        level, label, desc = "danger", "default", "默认开启，1479 种事件上报"

    return {
        "level": level,
        "label": label,
        "desc": desc,
        "flags": {
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": ness,
            "DISABLE_TELEMETRY": tele,
            "DISABLE_ERROR_REPORTING": err,
            "DO_NOT_TRACK": dnt,
        },
    }


def gather_server_params(binary_override=None):
    """采集服务端可见参数摘要，返回 dict。"""
    d = _read_claude_json()
    acc = d.get("oauthAccount") or {}
    binary = find_binary(binary_override)
    ver = os.path.basename(binary) if binary else "未知"
    ids = [
        ("账号 UUID", mask(acc.get("accountUuid"))),
        ("组织 UUID", mask(acc.get("organizationUuid"))),
        ("设备 ID", mask(d.get("userID"))),
        ("机器 ID", mask(d.get("machineID"))),
        ("邮箱", mask_email(acc.get("emailAddress"))),
    ]
    headers = [
        f"User-Agent: claude-cli/{ver}",
        f"X-Stainless-OS: {stainless_os()}",
        f"X-Stainless-Arch: {stainless_arch()}",
        "metadata.user_id（每次请求）",
    ]
    return {"version": ver, "ids": ids, "headers": headers, "level": "na"}


def gather_report(binary_override=None):
    """汇总四类检测，返回完整报告 dict。"""
    from datetime import datetime

    binary = find_binary(binary_override)
    st = binary_watermark_status(binary)
    domains = st["domains"] or _fallback_domains()
    keywords = st["keywords"] or FALLBACK_KEYWORDS
    base_url, source, _ = get_base_url()
    tz = get_iana_tz()
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "binary": binary,
        "binary_version": st["version"],
        "watermark_binary_status": st["status"],
        "watermark_binary_meta": st["meta"],
        "domains": domains,
        "keywords": keywords,
        "base_url": base_url,
        "base_url_source": source,
        "watermark": gather_watermark(base_url, domains, keywords, tz, st["status"]),
        "exposure": gather_exposure(base_url),
        "telemetry": gather_telemetry(),
        "server": gather_server_params(binary_override),
    }


# ---------- 可视化报告 ----------
_LEVEL_COLOR = {"safe": "#22c55e", "warn": "#f59e0b", "danger": "#ef4444", "na": "#94a3b8"}
_LEVEL_LABEL = {"safe": "低风险", "warn": "注意", "danger": "高风险", "na": "不适用"}


def _setup_cjk_font():
    """配置 matplotlib 中文字体，避免乱码。"""
    from matplotlib import font_manager
    import matplotlib.pyplot as plt

    for name in (
        "Microsoft YaHei", "PingFang SC", "SimHei",
        "Noto Sans CJK SC", "Arial Unicode MS", "DejaVu Sans",
    ):
        if any(f.name == name for f in font_manager.fontManager.ttflist):
            plt.rcParams["font.sans-serif"] = [name, "DejaVu Sans"]
            break
    plt.rcParams["axes.unicode_minus"] = False


def _overall_level(report):
    """根据各模块档位计算总体风险等级。"""
    order = {"safe": 0, "warn": 1, "danger": 2, "na": 0}
    levels = [
        report["watermark"]["level"],
        report["exposure"]["level"],
        report["telemetry"]["level"],
        report["server"]["level"],
    ]
    worst = max(levels, key=lambda x: order.get(x, 0))
    return worst


def render_report_chart(report, output_path, show=False):
    """将检测报告绘制成一张可读性强的 PNG 报告图。

    优先使用 matplotlib 输出 PNG；未安装时自动回退为 SVG。
    返回 (成功?, 输出路径或错误信息)。
    """
    try:
        import matplotlib

        if not show:
            matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        from matplotlib.gridspec import GridSpec
    except ImportError:
        svg_path = output_path.rsplit(".", 1)[0] + ".svg" if "." in output_path else output_path + ".svg"
        return render_report_svg(report, svg_path)

    _setup_cjk_font()

    overall = _overall_level(report)
    ocolor = _LEVEL_COLOR[overall]
    olbl = _LEVEL_LABEL[overall]

    fig = plt.figure(figsize=(14, 10), facecolor="#f8fafc")
    gs = GridSpec(3, 3, figure=fig, height_ratios=[0.55, 1.2, 1.0], hspace=0.45, wspace=0.35)

    # ── 标题栏 ──
    ax_title = fig.add_subplot(gs[0, :])
    ax_title.axis("off")
    title = "Claude Code 暴露自检报告"
    sub = (
        f"生成时间 {report['generated_at']}"
        f"  |  二进制 {report['binary_version'] or '未知'}"
    )
    if report["base_url"]:
        sub += f"\nANTHROPIC_BASE_URL: {report['base_url']}"
    ax_title.text(0.02, 0.72, title, fontsize=20, fontweight="bold", color="#0f172a", va="top")
    ax_title.text(0.02, 0.28, sub, fontsize=10, color="#64748b", va="top")
    badge = mpatches.FancyBboxPatch(
        (0.78, 0.15), 0.19, 0.7, boxstyle="round,pad=0.02",
        facecolor=ocolor, edgecolor="none", transform=ax_title.transAxes,
    )
    ax_title.add_patch(badge)
    ax_title.text(0.875, 0.5, f"总体\n{olbl}", ha="center", va="center",
                  fontsize=14, fontweight="bold", color="white", transform=ax_title.transAxes)

    wm = report["watermark"]
    exp = report["exposure"]
    tel = report["telemetry"]

    # ── 三卡片：水印 / 端点 / 遥测 ──
    cards = [
        (gs[1, 0], "[1] 客户端水印", wm["summary"], wm["level"],
         [f"二进制: {report['watermark_binary_status']}",
          f"known={'是' if wm['known'] else '否'}  labKw={'是' if wm['lab_kw'] else '否'}  cnTZ={'是' if wm['cn_tz'] else '否'}"]),
        (gs[1, 1], "[2] API 端点", exp["flow"], exp["level"],
         [f"端点: {'官方' if exp['official'] else '非官方'}",
          f"域名: {wm['host'] or '（未设，官方默认）'}"]),
        (gs[1, 2], "[3] 遥测档位", f"{tel['label']}\n{tel['desc']}", tel["level"],
         [f"{k}: {v or '未设'}" for k, v in list(tel["flags"].items())[:2]]),
    ]
    for spec, card_title, body, level, foot in cards:
        ax = fig.add_subplot(spec)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")
        color = _LEVEL_COLOR[level]
        ax.add_patch(mpatches.FancyBboxPatch(
            (0, 0), 1, 1, boxstyle="round,pad=0.02",
            facecolor="white", edgecolor=color, linewidth=2.5, transform=ax.transAxes,
        ))
        ax.text(0.05, 0.92, card_title, fontsize=12, fontweight="bold", color="#0f172a",
                va="top", transform=ax.transAxes)
        ax.text(0.05, 0.62, body, fontsize=9.5, color="#334155", va="top",
                wrap=True, transform=ax.transAxes)
        for i, line in enumerate(foot):
            ax.text(0.05, 0.22 - i * 0.1, line, fontsize=8, color="#64748b",
                    va="top", transform=ax.transAxes)

    # ── 敏感信息暴露条形图 ──
    ax_bar = fig.add_subplot(gs[2, :2])
    labels = [f["label"] for f in exp["fields"]]
    risks = [f["risk"] for f in exp["fields"]]
    bar_colors = ["#ef4444" if exp["level"] == "danger" else "#22c55e" for _ in risks]
    if exp["level"] == "danger":
        bar_colors = ["#fca5a5" if r >= 4 else "#fecaca" if r >= 2 else "#fee2e2" for r in risks]
    else:
        bar_colors = ["#bbf7d0" for _ in risks]
    y_pos = range(len(labels))
    ax_bar.barh(list(y_pos), risks, color=bar_colors, height=0.55, edgecolor="white")
    ax_bar.set_yticks(list(y_pos))
    ax_bar.set_yticklabels(labels, fontsize=10)
    ax_bar.set_xlim(0, 6)
    ax_bar.set_xlabel("敏感程度（相对值）", fontsize=9, color="#64748b")
    ax_bar.set_title("[4] 敏感信息 (system prompt 会携带)", fontsize=12, fontweight="bold", loc="left")
    ax_bar.spines["top"].set_visible(False)
    ax_bar.spines["right"].set_visible(False)
    for i, f in enumerate(exp["fields"]):
        note = f["note"]
        val = str(f["value"])
        if len(val) > 36:
            val = val[:33] + "..."
        ax_bar.text(risks[i] + 0.08, i, f"{val}  {note}", va="center", fontsize=8, color="#475569")

    # ── 服务端可见标识 ──
    ax_srv = fig.add_subplot(gs[2, 2])
    ax_srv.axis("off")
    ax_srv.set_title("[5] 服务端可见 (删水印也删不掉)", fontsize=12, fontweight="bold", loc="left")
    srv = report["server"]
    lines = ["身份标识:"] + [f"  · {a}: {b}" for a, b in srv["ids"]]
    lines += ["", "请求头 / 元数据:"] + [f"  · {h}" for h in srv["headers"]]
    ax_srv.text(0.02, 0.98, "\n".join(lines), fontsize=8.5, color="#334155",
                va="top", transform=ax_srv.transAxes)
    ax_srv.add_patch(mpatches.FancyBboxPatch(
        (0, 0), 1, 1, boxstyle="round,pad=0.02",
        facecolor="#fff7ed", edgecolor="#fdba74", linewidth=1.5, transform=ax_srv.transAxes, zorder=-1,
    ))

    fig.text(
        0.5, 0.01,
        "静态审计：基于本地配置 + 二进制逻辑，不代表实际线上字节；100% 坐实需抓包。"
        "  客户端水印移除 != 服务端不再识别你。",
        ha="center", fontsize=8, color="#94a3b8",
    )

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    if show:
        plt.show()
    plt.close(fig)
    return True, os.path.abspath(output_path)


def _svg_esc(text):
    """转义 SVG 文本中的特殊字符。"""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_report_svg(report, output_path):
    """无第三方依赖，输出 SVG 报告图（IDE 可直接预览）。"""
    overall = _overall_level(report)
    ocolor = _LEVEL_COLOR[overall]
    olbl = _LEVEL_LABEL[overall]
    wm = report["watermark"]
    exp = report["exposure"]
    tel = report["telemetry"]
    srv = report["server"]

    w, h = 960, 720
    lines = [
        f'<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">',
        f'<rect width="{w}" height="{h}" fill="#f8fafc"/>',
        f'<text x="24" y="42" font-size="24" font-weight="bold" fill="#0f172a">Claude Code 暴露自检报告</text>',
        f'<text x="24" y="68" font-size="12" fill="#64748b">'
        f'生成 { _svg_esc(report["generated_at"]) } | 二进制 { _svg_esc(report["binary_version"] or "未知") }</text>',
        f'<rect x="780" y="18" width="156" height="56" rx="10" fill="{ocolor}"/>',
        f'<text x="858" y="42" text-anchor="middle" font-size="14" font-weight="bold" fill="#fff">总体</text>',
        f'<text x="858" y="62" text-anchor="middle" font-size="14" font-weight="bold" fill="#fff">{_svg_esc(olbl)}</text>',
    ]

    cards = [
        (24, 90, "① 客户端水印", wm["summary"], wm["level"],
         [f"二进制: {report['watermark_binary_status']}",
          f"known={'是' if wm['known'] else '否'} labKw={'是' if wm['lab_kw'] else '否'} cnTZ={'是' if wm['cn_tz'] else '否'}"]),
        (334, 90, "② API 端点", exp["flow"], exp["level"],
         [f"{'官方' if exp['official'] else '非官方'} | {wm['host'] or '默认官方'}"]),
        (644, 90, "③ 遥测档位", f"{tel['label']} — {tel['desc']}", tel["level"], []),
    ]
    for x, y, title, body, level, foot in cards:
        color = _LEVEL_COLOR[level]
        lines.append(f'<rect x="{x}" y="{y}" width="292" height="150" rx="10" fill="#fff" stroke="{color}" stroke-width="2"/>')
        lines.append(f'<text x="{x + 12}" y="{y + 28}" font-size="13" font-weight="bold" fill="#0f172a">{_svg_esc(title)}</text>')
        for i, part in enumerate(_wrap_text(body, 28)[:3]):
            lines.append(f'<text x="{x + 12}" y="{y + 52 + i * 18}" font-size="11" fill="#334155">{_svg_esc(part)}</text>')
        for i, part in enumerate(foot):
            lines.append(f'<text x="{x + 12}" y="{y + 118 + i * 16}" font-size="10" fill="#64748b">{_svg_esc(part)}</text>')

    lines.append(f'<text x="24" y="268" font-size="14" font-weight="bold" fill="#0f172a">④ 敏感信息（system prompt 会携带）</text>')
    for i, f in enumerate(exp["fields"]):
        y = 292 + i * 36
        bar_w = min(f["risk"] * 18, 90)
        bar_c = "#ef4444" if exp["level"] == "danger" else "#22c55e"
        lines.append(f'<text x="24" y="{y + 14}" font-size="11" fill="#334155">{_svg_esc(f["label"])}</text>')
        lines.append(f'<rect x="130" y="{y}" width="{bar_w}" height="18" rx="4" fill="{bar_c}" opacity="0.75"/>')
        val = str(f["value"])
        if len(val) > 40:
            val = val[:37] + "…"
        lines.append(f'<text x="230" y="{y + 14}" font-size="10" fill="#475569">{_svg_esc(val)}</text>')

    lines.append(f'<text x="520" y="268" font-size="14" font-weight="bold" fill="#0f172a">⑤ 服务端可见（删水印也删不掉）</text>')
    lines.append(f'<rect x="520" y="280" width="416" height="200" rx="10" fill="#fff7ed" stroke="#fdba74"/>')
    sy = 302
    for label, val in srv["ids"]:
        lines.append(f'<text x="536" y="{sy}" font-size="10" fill="#334155">{_svg_esc(label)}: {_svg_esc(val)}</text>')
        sy += 18
    sy += 8
    for hdr in srv["headers"]:
        lines.append(f'<text x="536" y="{sy}" font-size="10" fill="#334155">· {_svg_esc(hdr)}</text>')
        sy += 18

    if report["base_url"]:
        lines.append(
            f'<text x="24" y="520" font-size="11" fill="#64748b">'
            f'ANTHROPIC_BASE_URL: {_svg_esc(report["base_url"])}</text>'
        )
    lines.append(
        f'<text x="24" y="700" font-size="10" fill="#94a3b8">'
        f'静态审计 · 不代表实际线上字节 · 100% 坐实需抓包 · 客户端水印移除 ≠ 服务端不再识别你</text>'
    )
    lines.append("</svg>")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return True, os.path.abspath(output_path)


def _wrap_text(text, width):
    """按字符宽度粗略换行，供 SVG 使用。"""
    text = str(text).replace("\n", " ")
    out, line = [], ""
    for ch in text:
        line += ch
        if len(line) >= width:
            out.append(line)
            line = ""
    if line:
        out.append(line)
    return out or [""]


# ---------- 终端表格输出 ----------
_RE_ANSI = re.compile(r"\033\[[0-9;]*m")
_LEVEL_BADGE = {
    "safe": lambda: ok("低"),
    "warn": lambda: warn("注意"),
    "danger": lambda: bad("高"),
    "na": lambda: C.DIM + "信息" + C.X,
}


def _plain(s):
    """去掉 ANSI 颜色码。"""
    return _RE_ANSI.sub("", str(s))


def _vis_len(s):
    """估算终端显示宽度（CJK 计 2，ASCII 计 1）。"""
    n = 0
    for ch in _plain(s):
        n += 2 if ord(ch) > 0x7F else 1
    return n


def _fit(s, max_w):
    """按显示宽度截断过长文本。"""
    s = _plain(s)
    if _vis_len(s) <= max_w:
        return s
    out = []
    w = 0
    for ch in s:
        cw = 2 if ord(ch) > 0x7F else 1
        if w + cw > max_w - 3:
            out.append("...")
            break
        out.append(ch)
        w += cw
    return "".join(out)


def _risk_badge(n):
    """敏感程度徽章。"""
    if n >= 4:
        return bad("高")
    if n >= 2:
        return warn("中")
    if n >= 1:
        return ok("低")
    return "-"


def _flag_yes(v):
    """是/否着色。"""
    return ok("是") if v else ok("否")


def _fmt_table(title, headers, rows, widths=None):
    """渲染 ASCII 表格并输出到终端。"""
    if not headers:
        return
    rows = rows or []
    plain = [[_plain(h) for h in headers]] + [[_plain(c) for c in r] for r in rows]
    ncol = len(headers)
    if widths is None:
        widths = []
        for c in range(ncol):
            w = max((_vis_len(r[c]) if c < len(r) else 0) for r in plain)
            widths.append(min(max(w + 2, 6), 46 if c == len(headers) - 1 else 38))

    def hline():
        return "+" + "+".join("-" * w for w in widths) + "+"

    def data_row(cells):
        parts = []
        for i, w in enumerate(widths):
            cell = str(cells[i]) if i < len(cells) else ""
            pad = w - _vis_len(cell)
            parts.append(" " + cell + " " * max(pad, 0))
        return "|" + "|".join(parts) + "|"

    if title:
        out("")
        out(f"{C.BOLD}{title}{C.X}")
    out(hline())
    out(data_row(headers))
    out(hline())
    for row in rows:
        out(data_row(row))
    out(hline())


def print_report_tables(report):
    """以表格形式输出完整检测报告，突出结论与风险。"""
    wm = report["watermark"]
    exp = report["exposure"]
    tel = report["telemetry"]
    srv = report["server"]
    overall = _overall_level(report)
    overall_txt = {"safe": ok("低风险"), "warn": warn("需注意"), "danger": bad("高风险")}[overall]

    out("")
    out(f"{C.BOLD}{'=' * 72}{C.X}")
    out(f"{C.BOLD}  Claude Code 暴露自检报告{C.X}  {C.DIM}{report['generated_at']}{C.X}")
    out(f"{C.DIM}  二进制: {report['binary_version'] or '未知'}  |  "
        f"水印二进制: {report['watermark_binary_status']}{C.X}")
    if report["base_url"]:
        out(f"{C.DIM}  ANTHROPIC_BASE_URL: {report['base_url']}  "
            f"(来源: {report['base_url_source']}){C.X}")
    out(f"{C.BOLD}{'=' * 72}{C.X}")

    # ── 总览：一眼看重点 ──
    wm_row = wm["summary"]
    if wm["status"] == "removed":
        wm_row = "已移除 (2.1.198+)"
    exp_row = "官方 Anthropic" if exp["official"] else _fit(exp["flow"], 28)
    _fmt_table(
        "【总览】四项检查结论",
        ["检查项", "结论", "风险"],
        [
            ["客户端水印", _fit(wm_row, 28), _LEVEL_BADGE[wm["level"]]()],
            ["API 端点", "官方直连" if exp["official"] else f"非官方 ({wm['host'] or '-'})",
             _LEVEL_BADGE[exp["level"]]()],
            ["遥测档位", f"{tel['label']}", _LEVEL_BADGE[tel["level"]]()],
            ["敏感数据流向", _fit(exp_row, 28), _LEVEL_BADGE[exp["level"]]()],
        ],
        widths=[14, 36, 8],
    )
    out(f"  >> 总体评估: {overall_txt}  |  "
        f"{warn('[!]')} 客户端水印移除 != 服务端不再识别你")

    # ── [1] 客户端水印 ──
    wm_rows = [["二进制状态", report["watermark_binary_status"],
                _fit(report["watermark_binary_meta"], 30)]]
    if wm["status"] == "removed":
        wm_rows.append(["客户端行为", "不再往 prompt 嵌撇号指纹", "-"])
        wm_rows.append(["服务端提醒", "[!] 账号/IP/UA 仍可见", warn("注意")])
    elif wm["official"]:
        wm_rows.append(["端点", "未设或非官方改写为官方", ok("不触发")])
    else:
        wm_rows += [
            ["端点 URL", _fit(wm["base_url"] or "-", 30), bad("非官方") if not wm["official"] else ok("官方")],
            ["域名 known", _flag_yes(wm["known"]), "域名黑名单匹配"],
            ["关键词 labKw", _flag_yes(wm["lab_kw"]), "AI 实验室关键词"],
            ["时区 cnTZ", _flag_yes(wm["cn_tz"]), _fit(wm["tz"] or "未知", 20)],
        ]
        if wm["marked"]:
            wm_rows.append(["指纹", f"撇号 {wm['apos_char']}  日期 {wm['date_sep']}", bad("已标记")])
        else:
            wm_rows.append(["指纹", "撇号/日期与官方不可区分", ok("未标记")])
    _fmt_table("[1] 客户端水印", ["项目", "值", "状态"], wm_rows, widths=[14, 34, 10])

    # ── [2] 敏感信息 ──
    exp_rows = []
    for f in exp["fields"]:
        exp_rows.append([
            f["label"],
            _fit(str(f["value"]), 32),
            _risk_badge(f["risk"]),
            _fit(f["note"] or "-", 16),
        ])
    exp_rows.append(["数据流向", _fit(exp["flow"], 32),
                     _LEVEL_BADGE[exp["level"]](), "-"])
    _fmt_table(
        "[2] 敏感信息 (system prompt 携带)",
        ["字段", "当前值", "敏感度", "说明"],
        exp_rows,
        widths=[14, 34, 8, 16],
    )
    if not exp["official"]:
        out(f"  {bad('[!] 重点')} 非官方端点: 用户名/项目结构/改动/规范全文均经第三方")

    # ── [3] 遥测 ──
    tel_rows = [
        ["当前档位", tel["label"], _LEVEL_BADGE[tel["level"]]()],
        ["说明", _fit(tel["desc"], 40), "-"],
    ]
    for k, v in tel["flags"].items():
        short = k.replace("CLAUDE_CODE_", "").replace("DISABLE_", "")
        tel_rows.append([short, v or "未设", ok("已开") if v else bad("未设")])
    _fmt_table("[3] 遥测状态", ["项目", "值", "状态"], tel_rows, widths=[28, 22, 8])
    if tel["level"] != "safe":
        out(f"  {warn('[建议]')} settings.json env 加: "
            f'"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"')

    # ── [4] 服务端可见 ──
    srv_rows = [[label, _fit(val, 40)] for label, val in srv["ids"]]
    srv_rows.append(["---", "---"])
    for hdr in srv["headers"]:
        if ":" in hdr:
            k, v = hdr.split(":", 1)
            srv_rows.append([k.strip(), _fit(v.strip(), 40)])
        else:
            srv_rows.append([_fit(hdr, 20), "每次请求携带"])
    srv_rows.append(["请求体 system", "工作目录/git/CLAUDE.md/OS/shell/邮箱"])
    srv_rows.append(["请求体 messages", "对话、代码、工具结果"])
    _fmt_table(
        "[4] 服务端可见 (删水印也删不掉)",
        ["项", "值 / 说明"],
        srv_rows,
        widths=[22, 46],
    )
    out(f"  {bad('[结论]')} 服务端凭 账号 + metadata.user_id + UA + X-Stainless 可稳定识别")

    # ── 关键提示 ──
    _fmt_table(
        "【关键提示】",
        ["#", "要点"],
        [
            ["1", "以上为本地配置+二进制静态审计，不代表实际线上字节"],
            ["2", "100% 坐实需抓包 (mitmproxy 等)"],
            ["3", "客户端水印移除 != 服务端不再识别你"],
            ["4", "走非官方端点时，敏感信息泄露风险 > 水印指纹"],
        ],
        widths=[4, 64],
    )
    out("")

# ========== 模块 1：水印状态 ==========
def check_watermark(base_url, domains, keywords, tz, status="present"):
    head("[1] 反蒸馏水印状态")
    if status == "removed":
        print(f"  判定：{ok('客户端水印已移除')}（2.1.198 起，二进制里无时区判断 / 撇号表 / 域名解码器）")
        print(f"  {C.DIM}客户端不再往 prompt 里嵌那个撇号指纹。{C.X}")
        print(f"  {warn('⚠ 但这不等于服务端没标记你。')}")
        print(f"  {C.DIM}服务端照样看得见你的账号、IP、请求头（User-Agent=claude-cli/<版本>）、"
              f"请求量与模式、以及你走没走号商端点。是否据此在服务端打标记 / 投毒（如 fake_tools 类），"
              f"本工具看不到、也无法保证——客户端删水印只删掉了「能被本地审计到」的那一层。{C.X}")
        return
    if status in ("obfuscation-changed", "read-error", "no-binary"):
        print(f"  {warn('⚠ 无法从二进制确认水印逻辑（' + status + '），以下判定按内置快照，仅供参考。')}")
    if is_official(base_url):
        if not base_url:
            print(f"  端点：{ok('未设 ANTHROPIC_BASE_URL（官方直连）')}")
        else:
            print(f"  端点：{ok(base_url + ' （官方 api.anthropic.com）')}")
        print(f"  判定：{ok('✅ 客户端水印不触发')}——不会往 prompt 里嵌撇号指纹。")
        print(f"  {C.DIM}（服务端仍可凭账号 / IP / 请求头识别你，见末尾诚实边界）{C.X}")
        return

    host = js_hostname(base_url)
    print(f"  端点：{warn(base_url)}")
    print(f"  域名：{host}")
    known, labKw, cnTZ = classify(host, domains, keywords, tz)

    def mk(flag, label, detail=""):
        mark = bad("● 命中") if flag else ok("○ 未命中")
        return f"    {label:16}{mark}  {detail}"

    hit_dom = next((d for d in domains if host == d or host.endswith("." + d)), None) if host else None
    hit_kw = next((k for k in (keywords or []) if k in host), None) if host else None
    print(mk(known, "域名黑名单 known", f"匹配到 {hit_dom}" if hit_dom else ""))
    print(mk(labKw, "关键词 labKw", f"含关键词 {hit_kw}" if hit_kw else ""))
    print(mk(cnTZ, "中国时区 cnTZ", f"你的时区 {tz}" if tz else "时区未知"))

    ch, cp, name = APOS[(known, labKw)]
    date_sep = "/" if cnTZ else "-"
    marked = known or labKw or cnTZ
    print()
    if marked:
        print(f"  → 你的请求会被打上：撇号 {bad(cp)} {C.DIM}{name}{C.X}，日期用 {bad(date_sep)}")
        print(f"     那行长这样：{bad(f'Today{ch}s date is 2026{date_sep}07{date_sep}01.')}")
        print(f"  {warn('⚠ 你走的是非官方端点，且已被打上可识别指纹。')}")
    else:
        print(f"  → 撇号为普通 ASCII、日期用 -，与官方基线不可区分。")
        print(f"  {ok('本次配置下没有可识别指纹，但你仍走了非官方端点（见下）。')}")


# ========== 模块 2：敏感信息暴露 ==========
def check_exposure(base_url):
    head("[2] 敏感信息暴露（system prompt 会携带什么）")
    official = is_official(base_url)
    cwd = os.getcwd()
    in_git = os.path.isdir(os.path.join(cwd, ".git")) or _has_git_parent(cwd)
    claudemd = None
    for cand in (os.path.join(cwd, "CLAUDE.md"), os.path.expanduser("~/.claude/CLAUDE.md")):
        if os.path.exists(cand):
            claudemd = cand
            break
    email = _read_oauth_email()

    fields = [
        ("工作目录绝对路径", cwd, "暴露用户名 + 完整项目结构（最敏感）"),
        ("git 仓库", "是（会带改动文件名）" if in_git else "否", ""),
        ("CLAUDE.md", claudemd or "无", "你的项目规范全文" if claudemd else ""),
        ("邮箱", email or "未读到", "来自 ~/.claude.json"),
        ("系统信息", "OS / 平台 / Shell", ""),
    ]
    for label, val, note in fields:
        line = f"    {label:18}{val}"
        if note:
            line += f"   {C.DIM}{note}{C.X}"
        print(line)

    print()
    if official:
        print(f"  流向：{ok('官方直连 → 只发给 Anthropic。')}")
    else:
        host = js_hostname(base_url)
        print(f"  流向：{bad('⚠ 非官方端点 → 以上字段全部经过第三方 ' + str(host))}")
        print(f"        {warn('用户名、项目结构、代码改动、项目规范，都会从这个中转方手里过一遍。')}")
        print(f"        {C.DIM}这比水印本身的隐私代价大得多。{C.X}")


def _has_git_parent(path):
    cur = path
    for _ in range(30):
        if os.path.isdir(os.path.join(cur, ".git")):
            return True
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return False


def _read_claude_json():
    p = os.path.expanduser("~/.claude.json")
    try:
        return json.load(open(p))
    except Exception:
        return {}


def _read_oauth_email():
    acct = _read_claude_json().get("oauthAccount") or {}
    return acct.get("emailAddress") or acct.get("email")


def mask(s, keep_head=6, keep_tail=4):
    if not s:
        return "（未读到）"
    s = str(s)
    if len(s) <= keep_head + keep_tail:
        return s
    return f"{s[:keep_head]}…{s[-keep_tail:]}"


def mask_email(e):
    if not e or "@" not in e:
        return e or "（未读到）"
    name, dom = e.split("@", 1)
    show = name[:2] if len(name) > 2 else name
    return f"{show}***@{dom}"


def stainless_os():
    import platform
    return {"Darwin": "MacOS", "Linux": "Linux", "Windows": "Windows"}.get(
        platform.system(), platform.system() or "Unknown")


def stainless_arch():
    import platform
    a = platform.machine().lower()
    return {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(a, a or "unknown")


# ========== 模块 3：遥测状态（复刻 VAs 三级）==========
def check_telemetry():
    head("[3] 遥测状态")
    env = dict(os.environ)
    sett = read_settings_env()

    def getv(key):
        return env.get(key) or sett.get(key)

    ness = getv("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
    tele = getv("DISABLE_TELEMETRY")
    err = getv("DISABLE_ERROR_REPORTING")
    dnt = getv("DO_NOT_TRACK")

    # VAs()：优先级 NONESSENTIAL > DISABLE_TELEMETRY > DO_NOT_TRACK > default
    if ness:
        level, desc, color = "essential-traffic", "最严——只留必要推理请求，遥测/错误上报/survey 全关", ok
    elif tele:
        level, desc, color = "no-telemetry", "运营指标关，但 Sentry/其它可能仍在", warn
    elif dnt:
        level, desc, color = "do-not-track", "遵循 DNT 标准，部分关闭", warn
    else:
        level, desc, color = "default", "遥测默认开启，1479 种事件会上报 Anthropic", bad

    print(f"  当前档位：{color(level)}  {C.DIM}{desc}{C.X}")
    for key, val in [
        ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", ness),
        ("DISABLE_TELEMETRY", tele),
        ("DISABLE_ERROR_REPORTING", err),
        ("DO_NOT_TRACK", dnt),
    ]:
        state = ok(f"= {val}") if val else bad("未设")
        print(f"    {key:44}{state}")

    if level != "essential-traffic":
        print()
        print(f"  {warn('建议：想关到最严，在 ~/.claude/settings.json 的 env 块加：')}")
        print(f'    {C.DIM}"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"{C.X}')


# ========== 模块 4：服务端可见参数 ==========
def check_server_params(binary_override=None):
    head("[4] 服务端可见参数（删了客户端水印也删不掉的识别信息）")
    d = _read_claude_json()
    acc = d.get("oauthAccount") or {}
    binary = find_binary(binary_override)
    ver = os.path.basename(binary) if binary else "未知"

    print(f"  {C.BOLD}身份标识（随请求上报，服务端据此稳定认出你）{C.X}")
    ids = [
        ("账号 UUID", "account_uuid", mask(acc.get("accountUuid"))),
        ("组织 UUID", "organizationUuid", mask(acc.get("organizationUuid"))),
        ("设备/安装 ID", "userID", mask(d.get("userID"))),
        ("机器 ID", "machineID", mask(d.get("machineID"))),
        ("邮箱", "emailAddress", mask_email(acc.get("emailAddress"))),
    ]
    for label, key, val in ids:
        print(f"    {label:12}{key:18}{val}")
    print(f"    {C.DIM}→ 请求体 metadata.user_id 由 account_uuid + device_id + session_id 派生，每次推理请求都带{C.X}")

    print(f"\n  {C.BOLD}请求头（客户端指纹）{C.X}")
    hdrs = [
        ("User-Agent", f"claude-cli/{ver}"),
        ("x-app", "cli / cli-bg（后台）"),
        ("X-Claude-Code-Session-Id", "每次会话生成的会话 ID"),
        ("anthropic-version / -beta", "API 版本 + 一串 beta 特性开关"),
        ("anthropic-client-platform", "平台标识"),
        ("X-Stainless-OS", stainless_os()),
        ("X-Stainless-Arch", stainless_arch()),
        ("X-Stainless-Runtime", "bun（Claude Code 为 Bun 编译，推断）"),
        ("授权", "x-api-key 或 authorization: Bearer <token>"),
    ]
    for k, v in hdrs:
        print(f"    {k:28}{v}")

    print(f"\n  {C.BOLD}请求体{C.X}")
    print(f"    {'system':10}系统提示（工作目录 / git / CLAUDE.md / OS / shell / 邮箱，见模块②）")
    print(f"    {'messages':10}你的对话、代码、工具执行结果")
    print(f"    {'tools':10}工具定义")

    print()
    print(f"  {bad('→ 结论')}：删客户端水印删不掉这些。服务端凭 账号凭证 + metadata.user_id + "
          f"User-Agent 版本 + X-Stainless 的 OS/架构，就能稳定识别你。")
    print(f"  {C.DIM}诚实边界：静态审计确认「客户端会装配这些字段/头」；实际上线字节、会话值、"
          f"metadata.user_id 是否哈希、X-Stainless 是否真发，需抓包坐实。{C.X}")


# ========== 模块 5：文本反向检测 ==========
def scan_text(text):
    head("[文本反向检测] 扫描水印")
    found = []
    for cp_char, (known, labKw) in CP_TO_FLAGS.items():
        cnt = text.count(cp_char)
        if cnt:
            _, cp, name = APOS[(known, labKw)]
            found.append((cp, name, cnt, known, labKw))

    has_slash_date = bool(re.search(r"\b\d{4}/\d{2}/\d{2}\b", text))
    has_today = bool(re.search(r"Today.s date is", text))

    if not found and not has_slash_date:
        print(f"  {ok('✅ 未发现水印撇号，日期也无斜杠格式——这段文本没有被打标记的迹象。')}")
        return

    if has_today:
        print(f"  {C.DIM}文本中出现 “Today's date is” 行（水印注入位置）。{C.X}")
    for cp, name, cnt, known, labKw in found:
        parts = []
        if known:
            parts.append("命中域名黑名单")
        if labKw:
            parts.append("命中关键词")
        print(f"  {bad('● 发现水印撇号')} {cp} {C.DIM}{name}{C.X} ×{cnt} → {bad(' + '.join(parts))}")
    if has_slash_date:
        print(f"  {bad('● 日期为斜杠格式')} 2026/07/01 → {bad('命中中国大陆时区 cnTZ')}")
    if not found and has_slash_date:
        print(f"  {warn('（只有斜杠日期、无特殊撇号：可能是 cnTZ 命中但域名/关键词都没中）')}")


# ---------- 主流程 ----------
def full_check(binary_override, *, text_only=False, output_path=None, show_chart=False):
    """运行完整自检；默认同时输出全量格式化文字报告与可视化图。"""
    report = gather_report(binary_override)

    _print_text_report(report, binary_override)

    if text_only:
        return report

    if output_path is None:
        output_path = os.path.join(os.getcwd(), "claude_expose_report.png")

    out("")
    ok_chart, result = render_report_chart(report, output_path, show=show_chart)
    if ok_chart:
        out(f"报告图已保存: {result}")
        if not show_chart:
            out("提示: 在 IDE 中打开上述图片，或加 --show 在窗口预览。")
    else:
        out(f"{warn('[!] ' + result)}，未能生成报告图。")
    return report


def _print_text_report(report, binary_override):
    """终端表格版完整报告。"""
    print_report_tables(report)


def _fallback_domains():
    # 回退时只放国家码兜底；真正的 147 项以二进制解码为准。
    return ["cn"]


# ---------- 检测数据快照导出 ----------
def dump_data(binary_override):
    from datetime import datetime

    binary = find_binary(binary_override)
    st = binary_watermark_status(binary)
    ver = st["version"]
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    print(f"{C.BOLD}═══ Claude Code 反蒸馏水印 · 检测数据快照 ═══{C.X}")
    print(f"{C.DIM}生成时间：{stamp}{C.X}")
    print(f"{C.DIM}二进制：{binary}（{ver}）{C.X}")

    if st["status"] == "removed":
        print(f"\n{ok('★ 此版本已移除客户端水印')}——{st['meta']}。")
        print(f"{C.DIM}水印相关的时区判断、四撇号表、147 域名 + 11 关键词解码器均已从二进制删除；"
              f"currentDate 恢复为普通 `Today's date is <date>.`。客户端已无检测数据可导出。{C.X}")
        print(f"{warn('注意')}{C.DIM}：这仅代表客户端不再嵌指纹；服务端是否仍用账号 / IP / 请求头 / "
              f"流量模式标记你，属黑盒，本工具无法判断。{C.X}")
        return
    if st["status"] != "present":
        print(f"\n{warn('无法导出：' + st['status'])}——{st['meta']}。")
        return

    domains, keywords, meta = st["domains"], st["keywords"], st["meta"]
    print(f"{C.DIM}水印：存在   {meta}{C.X}")

    head(f"AI 实验室关键词（labKw，子串匹配，共 {len(keywords)} 项 → 9 家公司）")
    for i, k in enumerate(keywords, 1):
        print(f"  {i:2}. {k:12} {C.DIM}{KW_COMPANY.get(k, '?')}{C.X}")

    head(f"域名黑名单（known，精确/后缀匹配，共 {len(domains)} 项）")
    for i, d in enumerate(domains, 1):
        print(f"  {i:3}. {d}")

    head("8 态水印参照（撇号 × 日期分隔符）")
    print(f"  {'known':7}{'labKw':7}{'cnTZ':6}{'撇号':10}{'日期':6}")
    for known in (False, True):
        for labKw in (False, True):
            for cnTZ in (False, True):
                ch, cp, _ = APOS[(known, labKw)]
                sep = "/" if cnTZ else "-"
                y = lambda b: "T" if b else "F"
                print(f"  {y(known):7}{y(labKw):7}{y(cnTZ):6}{cp:10}{sep:6}")

    print()
    print(f"{C.DIM}说明：撇号 U+0027=都没中 / U+2019=known / U+02BC=labKw / U+02B9=两者都中；"
          f"日期 / 表示命中中国大陆时区（Asia/Shanghai|Asia/Urumqi）。{C.X}")


def main():
    _ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="Claude Code 暴露自检（本地静态）")
    ap.add_argument("--binary", help="手动指定 Claude Code 二进制路径")
    ap.add_argument("--scan-file", help="检测某文件文本里的水印")
    ap.add_argument("--scan-stdin", action="store_true", help="从 stdin 读文本做水印检测")
    ap.add_argument("--scan-text", help="直接传入一段文本做水印检测")
    ap.add_argument("--dump-data", action="store_true", help="导出当前二进制里的检测数据快照（147 域名 + 11 关键词 + 8 态）")
    ap.add_argument("--server-params", action="store_true", help="只看服务端可见参数（删了水印也删不掉的识别信息）")
    ap.add_argument("--text", action="store_true", help="仅终端文字输出，不生成报告图")
    ap.add_argument("--output", "-o", help="报告图输出路径（默认 ./claude_expose_report.png）")
    ap.add_argument("--show", action="store_true", help="生成报告图并在窗口中预览")
    args = ap.parse_args()

    if args.server_params:
        check_server_params(args.binary)
    elif args.dump_data:
        dump_data(args.binary)
    elif args.scan_file:
        scan_text(open(args.scan_file, encoding="utf-8", errors="replace").read())
    elif args.scan_stdin:
        scan_text(sys.stdin.read())
    elif args.scan_text is not None:
        scan_text(args.scan_text)
    else:
        full_check(
            args.binary,
            text_only=args.text,
            output_path=args.output,
            show_chart=args.show,
        )


if __name__ == "__main__":
    main()
