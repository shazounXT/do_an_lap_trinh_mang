"""
toolkit/dns_tools.py
Công cụ tra cứu DNS cho mục tiêu kiểm thử.
Chức năng:
  - dns_lookup(): phân giải hostname → danh sách IP, MX, NS records
"""
import socket
from typing import Any, Dict, List

from utils.logger import get_logger

logger = get_logger("toolkit.dns")


def dns_lookup(hostname: str) -> Dict[str, Any]:
    """
    Tra cứu DNS cho hostname.

    Trả về dict:
        hostname    : str
        a_records   : List[str]   # IPv4
        aaaa_records: List[str]   # IPv6
        mx_records  : List[str]
        ns_records  : List[str]
        error       : str | None
    """
    result: Dict[str, Any] = {
        "hostname":     hostname,
        "a_records":    [],
        "aaaa_records": [],
        "mx_records":   [],
        "ns_records":   [],
        "error":        None,
    }

    # ── A / AAAA records ──────────────────────────────────────
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            family, _, _, _, addr = info
            ip = addr[0]
            if family == socket.AF_INET and ip not in result["a_records"]:
                result["a_records"].append(ip)
            elif family == socket.AF_INET6 and ip not in result["aaaa_records"]:
                result["aaaa_records"].append(ip)
        logger.info("[DNS] %s → A: %s", hostname, result["a_records"])
    except socket.gaierror as e:
        result["error"] = f"Không thể phân giải hostname: {e}"
        logger.warning("[DNS] Lỗi phân giải %s: %s", hostname, e)
        return result

    # ── MX records (qua socket DNS raw query thay thế dnspython) ─
    # Dùng một cách đơn giản: thử resolve mail. subdomain
    for prefix in ["mail", "smtp", "mx", "mail1", "mail2"]:
        try:
            mx_host = f"{prefix}.{hostname}"
            socket.getaddrinfo(mx_host, None)
            result["mx_records"].append(mx_host)
        except socket.gaierror:
            pass

    # ── NS records – thử các subdomain phổ biến của nameserver ──
    for prefix in ["ns1", "ns2", "ns3", "dns1", "dns2"]:
        try:
            ns_host = f"{prefix}.{hostname}"
            socket.getaddrinfo(ns_host, None)
            result["ns_records"].append(ns_host)
        except socket.gaierror:
            pass

    logger.debug("[DNS] Kết quả đầy đủ cho %s: %s", hostname, result)
    return result


def get_primary_ip(hostname: str) -> str:
    """Trả về địa chỉ IP đầu tiên của hostname, hoặc chuỗi rỗng nếu thất bại."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""
