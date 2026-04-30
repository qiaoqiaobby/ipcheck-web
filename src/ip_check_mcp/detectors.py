"""
Pure data collection functions for network environment detection.
No terminal rendering — returns structured data only.
"""

import socket
import ipaddress
import os
import sys
import subprocess
import datetime
import platform

try:
    from zoneinfo import ZoneInfo
except ImportError:
    try:
        from backports.zoneinfo import ZoneInfo  # type: ignore
    except ImportError:
        ZoneInfo = None

IS_WIN = platform.system() == "Windows"

KNOWN_DNS = {
    "1.1.1.1": "Cloudflare (US)",
    "1.0.0.1": "Cloudflare (US)",
    "1.1.1.2": "Cloudflare for Families (US)",
    "1.0.0.2": "Cloudflare for Families (US)",
    "1.1.1.3": "Cloudflare for Families (US)",
    "1.0.0.3": "Cloudflare for Families (US)",
    "8.8.8.8": "Google Public DNS (US)",
    "8.8.4.4": "Google Public DNS (US)",
    "9.9.9.9": "Quad9 (US)",
    "149.112.112.112": "Quad9 (US)",
    "208.67.222.222": "OpenDNS/Cisco (US)",
    "208.67.220.220": "OpenDNS/Cisco (US)",
    "223.5.5.5": "AliDNS (CN)",
    "223.6.6.6": "AliDNS (CN)",
    "119.29.29.29": "DNSPod (CN)",
    "182.254.116.116": "DNSPod (CN)",
    "114.114.114.114": "114DNS (CN)",
    "114.114.115.115": "114DNS (CN)",
    "180.76.76.76": "BaiduDNS (CN)",
    "1.2.4.8": "CNNIC (CN)",
    "210.2.4.8": "CNNIC (CN)",
    "94.140.14.14": "AdGuard (CY)",
    "94.140.15.15": "AdGuard (CY)",
    "185.228.168.9": "CleanBrowsing (US)",
    "185.228.169.9": "CleanBrowsing (US)",
    "76.76.2.0": "Alternate DNS (US)",
    "76.76.10.0": "Alternate DNS (US)",
}


def dns_label(ip: str) -> str:
    if ip in KNOWN_DNS:
        return KNOWN_DNS[ip]
    try:
        if ipaddress.ip_address(ip).is_private:
            return "LAN Router"
    except Exception:
        pass
    return "Unknown"


def _make_zone(name: str):
    if not ZoneInfo or not name:
        return None
    try:
        return ZoneInfo(name)
    except Exception:
        return None


def _utc_str(offset) -> str:
    total = int(offset.total_seconds())
    h, r = divmod(abs(total), 3600)
    sign = "+" if total >= 0 else "-"
    return f"UTC{sign}{h:02d}:{r // 60:02d}"


def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Failed"


def get_ipv6() -> str | None:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip not in ("", "::"):
            return ip
    except Exception:
        pass
    return None


def get_dns_servers() -> list[dict]:
    servers: list[str] = []

    if IS_WIN:
        try:
            r = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientServerAddress -AddressFamily IPv4 | "
                    "Select-Object -ExpandProperty ServerAddresses",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
            )
            seen = set()
            for line in r.stdout.splitlines():
                ip = line.strip()
                if not ip:
                    continue
                try:
                    ipaddress.ip_address(ip)
                    if ip not in seen:
                        seen.add(ip)
                        servers.append(ip)
                except ValueError:
                    pass
        except Exception:
            pass
    else:
        try:
            seen = set()
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        ip = line.split()[1]
                        if ip not in seen:
                            seen.add(ip)
                            servers.append(ip)
        except Exception:
            pass
        if not servers:
            try:
                r = subprocess.run(
                    ["scutil", "--dns"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                seen = set()
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("nameserver["):
                        ip = line.split(":", 1)[1].strip()
                        if ip not in seen:
                            seen.add(ip)
                            servers.append(ip)
            except Exception:
                pass

    return [{"ip": ip, "label": dns_label(ip)} for ip in servers]


def get_public_info() -> dict:
    import requests

    try:
        resp = requests.get(
            "http://ip-api.com/json/",
            params={
                "fields": "status,message,country,regionName,city,isp,org,proxy,hosting,query,timezone"
            },
            timeout=6,
        )
        return resp.json()
    except Exception as e:
        return {"status": "fail", "message": str(e)}


def get_ip_risk(ip: str) -> dict:
    import requests

    try:
        resp = requests.get(
            f"https://proxycheck.io/v2/{ip}",
            params={"risk": 1, "vpn": 1, "asn": 1},
            timeout=6,
        )
        data = resp.json().get(ip, {})
        risk = data.get("risk")
        score = int(risk) if risk is not None else None
        level = None
        if score is not None:
            if score < 30:
                level = "low"
            elif score < 70:
                level = "medium"
            else:
                level = "high"
        return {
            "score": score,
            "level": level,
            "type": data.get("type", ""),
            "proxy": data.get("proxy", "") == "yes",
        }
    except Exception as e:
        return {"error": str(e)}


def get_stopforumspam(ip: str) -> dict:
    import requests

    try:
        resp = requests.get(
            "https://api.stopforumspam.org/api",
            params={"json": 1, "ip": ip},
            timeout=6,
        )
        data = resp.json().get("ip", {})
        return {
            "appears": bool(data.get("appears")),
            "confidence": float(data.get("confidence", 0)),
            "frequency": int(data.get("frequency", 0)),
            "last_seen": (data.get("lastseen") or "")[:10] or None,
        }
    except Exception as e:
        return {"error": str(e)}


def get_proxy_envs() -> dict:
    seen: dict[str, str] = {}
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ]:
        val = os.environ.get(key)
        if val and val not in seen.values():
            seen[key.upper()] = val
    return seen


def get_timezone_info(pub_timezone: str | None = None) -> dict:
    cli_dt = datetime.datetime.now().astimezone()
    cli_offset = cli_dt.utcoffset()

    tz_env = os.environ.get("TZ", "")
    if tz_env:
        cli_tz_name = tz_env
        is_iana = True
    elif IS_WIN:
        cli_tz_name = ""
        try:
            r = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "[System.TimeZoneInfo]::Local.Id",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                encoding="utf-8",
            )
            cli_tz_name = r.stdout.strip()
        except Exception:
            pass
        if not cli_tz_name:
            cli_tz_name = datetime.datetime.now().astimezone().tzname() or "Unknown"
        is_iana = False
    else:
        cli_tz_name = datetime.datetime.now().astimezone().tzname() or "Unknown"
        is_iana = False

    result = {
        "cli_timezone": cli_tz_name,
        "cli_utc_offset": _utc_str(cli_offset),
    }

    if pub_timezone:
        result["public_timezone"] = pub_timezone
        pub_zi = _make_zone(pub_timezone)
        if pub_zi:
            pub_offset = datetime.datetime.now(pub_zi).utcoffset()
            result["public_utc_offset"] = _utc_str(pub_offset)
            if is_iana:
                result["match"] = cli_tz_name == pub_timezone
            elif pub_offset is not None:
                result["match"] = cli_offset == pub_offset
            else:
                result["match"] = None

    return result


def check_all() -> dict:
    lan_ip = get_lan_ip()
    ipv6 = get_ipv6()
    dns = get_dns_servers()
    pub = get_public_info()
    proxy_envs = get_proxy_envs()

    result = {
        "network": {
            "lan_ip": lan_ip,
            "ipv6": ipv6,
            "ipv6_disabled": ipv6 is None,
            "dns_servers": dns,
        },
        "proxy_env": proxy_envs,
    }

    if pub.get("status") == "success":
        result["public_ip"] = {
            "ip": pub.get("query"),
            "country": pub.get("country"),
            "region": pub.get("regionName"),
            "city": pub.get("city"),
            "isp": pub.get("isp"),
            "org": pub.get("org"),
            "timezone": pub.get("timezone"),
            "is_proxy": pub.get("proxy", False),
            "is_hosting": pub.get("hosting", False),
        }

        pub_ip = pub.get("query", "")
        if pub.get("hosting") or pub.get("proxy"):
            result["ip_risk"] = get_ip_risk(pub_ip)
            result["abuse_record"] = get_stopforumspam(pub_ip)

        result["timezone"] = get_timezone_info(pub.get("timezone"))
    else:
        result["public_ip"] = {"error": pub.get("message", "Unknown error")}
        result["timezone"] = get_timezone_info()

    return result
