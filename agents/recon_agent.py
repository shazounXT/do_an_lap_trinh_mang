"""
agents/recon_agent.py
ReconAgent – Thu thập thông tin mục tiêu (Reconnaissance Phase).

Công việc:
  1. DNS Lookup    → hostname → IP addresses, MX, NS
  2. Port Scanning → các cổng TCP phổ biến đang mở
  3. Subdomain Enum → các subdomain tồn tại

Sử dụng các toolkit: dns_tools, port_scan_tools, subdomain_tools
"""
import urllib.parse
from typing import Callable

from models.scan_result import ReconData
from toolkit.dns_tools import dns_lookup, get_primary_ip
from toolkit.port_scan_tools import port_scan
from toolkit.subdomain_tools import subdomain_enum
from utils.logger import get_logger

logger = get_logger("agent.recon")


class ReconAgent:
    """
    Agent thu thập thông tin cơ bản về mục tiêu.
    Chạy tuần tự: DNS → Port Scan → Subdomain Enum.
    """

    def __init__(self, progress_callback: Callable[[int, str], None] | None = None):
        """
        Args:
            progress_callback: Hàm nhận (% hoàn thành, thông báo) để cập nhật UI real-time.
        """
        self._progress = progress_callback or (lambda p, m: None)

    def _update(self, pct: int, msg: str) -> None:
        logger.info("[RECON] %d%% – %s", pct, msg)
        self._progress(pct, msg)

    def run(self, target_url: str) -> ReconData:
        """
        Thực thi toàn bộ giai đoạn Reconnaissance.

        Args:
            target_url: URL đầy đủ của mục tiêu (ví dụ: http://testphp.vulnweb.com)

        Returns:
            ReconData chứa kết quả thu thập.
        """
        logger.info("[RECON] Bắt đầu thu thập thông tin: %s", target_url)
        self._update(5, "Phân tích URL mục tiêu…")

        # ── Phân tích URL ──────────────────────────────────────────
        parsed   = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname or target_url.replace("http://", "").replace("https://", "").split("/")[0]

        result = ReconData(
            target_url=target_url,
            hostname=hostname,
        )

        # ── Bước 1: DNS Lookup ────────────────────────────────────
        self._update(10, f"Tra cứu DNS cho {hostname}…")
        try:
            dns_data = dns_lookup(hostname)
            result.ip_addresses = dns_data.get("a_records", [])
            result.dns_records  = {
                "A":    dns_data.get("a_records", []),
                "AAAA": dns_data.get("aaaa_records", []),
                "MX":   dns_data.get("mx_records", []),
                "NS":   dns_data.get("ns_records", []),
            }
            if dns_data.get("error"):
                result.raw_errors.append(f"DNS: {dns_data['error']}")
                logger.warning("[RECON] DNS lỗi: %s", dns_data["error"])
            else:
                logger.info("[RECON] DNS thành công: %s → %s", hostname, result.ip_addresses)
        except Exception as exc:
            result.raw_errors.append(f"DNS lookup thất bại: {exc}")
            logger.error("[RECON] DNS exception: %s", exc)

        # ── Bước 2: Port Scanning ─────────────────────────────────
        self._update(25, f"Quét cổng TCP trên {hostname}…")
        scan_target = result.ip_addresses[0] if result.ip_addresses else hostname
        try:
            result.open_ports = port_scan(scan_target)
            logger.info("[RECON] Port scan: %d cổng mở", len(result.open_ports))
        except Exception as exc:
            result.raw_errors.append(f"Port scan thất bại: {exc}")
            logger.error("[RECON] Port scan exception: %s", exc)

        # ── Bước 3: Subdomain Enumeration ─────────────────────────
        self._update(40, f"Liệt kê subdomain của {hostname}…")
        try:
            result.subdomains = subdomain_enum(hostname)
            logger.info("[RECON] Subdomain: %d tìm thấy", len(result.subdomains))
        except Exception as exc:
            result.raw_errors.append(f"Subdomain enum thất bại: {exc}")
            logger.error("[RECON] Subdomain exception: %s", exc)

        # ── Bước 4: Lấy thông tin server từ HTTP header ────────────
        self._update(48, "Lấy thông tin server…")
        try:
            import urllib.request
            import ssl
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "PentestAI-Scanner/1.0"},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                server = resp.headers.get("Server", "")
                powered = resp.headers.get("X-Powered-By", "")
                parts = [p for p in [server, powered] if p]
                result.server_info = " | ".join(parts) if parts else "Không rõ"
        except Exception:
            result.server_info = "Không xác định"

        self._update(50, "Hoàn thành Reconnaissance!")
        logger.info("[RECON] Hoàn tất. IPs=%s, ports=%d, subs=%d",
                    result.ip_addresses, len(result.open_ports), len(result.subdomains))
        return result
