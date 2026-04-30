from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from . import detectors

mcp = FastMCP(
    "ip-check",
    instructions="Network environment diagnostic tool for AI developers. "
    "Checks IP reputation, DNS leakage, timezone consistency, "
    "and proxy configuration for LLM API access.",
)


@mcp.tool()
def check_all() -> dict:
    """Run a full network environment diagnostic.

    Checks LAN IP, IPv6 status, DNS servers, public IP info,
    proxy detection, IP risk score, abuse records, and timezone consistency.
    Use this to verify if the current network environment is suitable
    for AI tools like Claude Code, OpenAI API, or Cursor.
    """
    return detectors.check_all()


@mcp.tool()
def check_ip_risk(
    ip: Annotated[str, Field(description="Public IP address to check")],
) -> dict:
    """Check risk score and abuse records for a specific IP address.

    Queries proxycheck.io for risk scoring and StopForumSpam for abuse history.
    Returns risk level (low/medium/high), proxy detection status, and abuse records.
    """
    risk = detectors.get_ip_risk(ip)
    abuse = detectors.get_stopforumspam(ip)
    return {"ip": ip, "risk": risk, "abuse": abuse}


@mcp.tool()
def check_dns() -> dict:
    """Check current DNS server configuration.

    Detects configured DNS servers and identifies whether they are
    domestic (CN) or international providers. Domestic DNS can leak
    your real geographic location to AI services.
    """
    servers = detectors.get_dns_servers()
    has_cn_dns = any("(CN)" in s["label"] for s in servers)
    return {
        "servers": servers,
        "has_cn_dns": has_cn_dns,
        "warning": "Domestic DNS detected, may leak real location"
        if has_cn_dns
        else None,
    }


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
