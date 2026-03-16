"""
toolkit/subdomain_tools.py
Công cụ liệt kê subdomain bằng cách thử các tên phổ biến.
Phương pháp: brute-force wordlist + DNS resolution.
"""
import concurrent.futures
import socket
from typing import List

from utils.logger import get_logger

logger = get_logger("toolkit.subdomain")

# Wordlist các subdomain phổ biến
SUBDOMAIN_WORDLIST: List[str] = [
    "www", "mail", "ftp", "admin", "login", "blog", "shop",
    "api", "dev", "test", "stage", "staging", "portal",
    "app", "apps", "mobile", "m", "secure", "vpn",
    "ns1", "ns2", "dns", "smtp", "pop", "imap",
    "webmail", "cpanel", "whm", "plesk",
    "cdn", "static", "assets", "img", "images",
    "forum", "support", "help", "docs", "wiki",
    "beta", "alpha", "demo", "old", "new",
    "db", "mysql", "sql", "mongo", "redis",
    "git", "gitlab", "jenkins", "ci", "jira",
    "upload", "download", "files", "media",
    "monitor", "status", "health",
    "intranet", "internal", "local",
    "cloud", "s3", "storage",
    "payment", "pay", "billing",
    "news", "press", "careers",
    "en", "vn", "www2", "web",
    "mx1", "mx2", "relay", "gateway",
    "proxy", "lb", "balancer",
]


def _resolve_subdomain(subdomain: str, domain: str) -> str | None:
    """Phân giải một subdomain. Trả về hostname nếu tồn tại, None nếu không."""
    full_host = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(full_host, None)
        return full_host
    except (socket.gaierror, socket.timeout):
        return None


def subdomain_enum(domain: str, max_workers: int = 20) -> List[str]:
    """
    Liệt kê các subdomain tồn tại của `domain` bằng brute-force wordlist.

    Args:
        domain      : Domain gốc (ví dụ: "example.com")
        max_workers : Số luồng song song

    Returns:
        Danh sách subdomain hợp lệ tìm được.
    """
    # Loại bỏ scheme nếu có
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    logger.info("[SUBDOMAIN] Bắt đầu liệt kê subdomain cho: %s", domain)
    found: List[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_resolve_subdomain, sub, domain): sub
            for sub in SUBDOMAIN_WORDLIST
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                logger.debug("[SUBDOMAIN] Tìm thấy: %s", result)

    found.sort()
    logger.info("[SUBDOMAIN] Tổng cộng %d subdomain cho %s", len(found), domain)
    return found
