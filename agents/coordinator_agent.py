"""
agents/coordinator_agent.py
CoordinatorAgent – Điều phối toàn bộ pipeline kiểm thử bảo mật.

Pipeline:
  Phase 1: Reconnaissance  (ReconAgent)
       ↓
  Phase 2: Vulnerability   (VulnerabilityAgent)
       ↓
  Phase 3: Report          (ReportAgent)

Nhận progress_callback để cập nhật trạng thái real-time cho frontend.
"""
import traceback
from datetime import datetime
from typing import Callable

from agents.recon_agent import ReconAgent
from agents.report_agent import ReportAgent
from agents.vulnerability_agent import VulnerabilityAgent
from models.scan_result import ScanResult
from utils.logger import get_logger

logger = get_logger("agent.coordinator")


class CoordinatorAgent:
    """
    Agent điều phối pipeline pentest 3 giai đoạn.

    Sử dụng:
        coordinator = CoordinatorAgent(scan_result, progress_callback)
        coordinator.run()
    """

    def __init__(
        self,
        scan_result: ScanResult,
        progress_callback: Callable[[int, str], None] | None = None,
    ):
        """
        Args:
            scan_result       : Object ScanResult sẽ được cập nhật liên tục trong quá trình chạy.
            progress_callback : Hàm nhận (% hoàn thành, thông báo giai đoạn).
        """
        self.scan_result = scan_result
        self._cb         = progress_callback or (lambda p, m: None)

    def _update(self, pct: int, phase: str, msg: str) -> None:
        """Cập nhật trạng thái scan và gọi callback."""
        self.scan_result.progress = pct
        self.scan_result.phase    = phase
        logger.info("[COORDINATOR] %d%% [%s] %s", pct, phase, msg)
        self._cb(pct, msg)

    def run(self) -> ScanResult:
        """
        Chạy toàn bộ pipeline pentest.

        Returns:
            ScanResult được cập nhật với kết quả từ tất cả các agent.
        """
        result = self.scan_result
        result.status     = "running"
        result.started_at = datetime.now()
        target_url        = result.target_url

        logger.info("[COORDINATOR] Bắt đầu pipeline cho: %s", target_url)
        self._update(2, "Khởi động", f"Chuẩn bị kiểm thử {target_url}…")

        # ══════════════════════════════════════════════════════════
        # PHASE 1: RECONNAISSANCE
        # ══════════════════════════════════════════════════════════
        self._update(5, "Phase 1: Reconnaissance", "Thu thập thông tin mục tiêu…")
        try:
            recon_agent = ReconAgent(
                progress_callback=lambda p, m: self._update(p, "Phase 1: Reconnaissance", m)
            )
            result.recon_data = recon_agent.run(target_url)
            self._update(50, "Phase 1: Hoàn thành", "✓ Reconnaissance hoàn tất")
            logger.info("[COORDINATOR] Phase 1 hoàn thành")
        except Exception as exc:
            logger.error("[COORDINATOR] Phase 1 lỗi: %s\n%s", exc, traceback.format_exc())
            result.raw_errors_phase1 = str(exc)
            # Tiếp tục với dữ liệu rỗng
            from models.scan_result import ReconData
            result.recon_data = ReconData(target_url=target_url)

        # ══════════════════════════════════════════════════════════
        # PHASE 2: VULNERABILITY ASSESSMENT
        # ══════════════════════════════════════════════════════════
        self._update(52, "Phase 2: Vulnerability Assessment", "Đánh giá lỗ hổng bảo mật…")
        try:
            vuln_agent = VulnerabilityAgent(
                progress_callback=lambda p, m: self._update(p, "Phase 2: Vulnerability Assessment", m)
            )
            result.vuln_data = vuln_agent.run(target_url, result.recon_data)
            self._update(90, "Phase 2: Hoàn thành", "✓ Vulnerability assessment hoàn tất")
            logger.info("[COORDINATOR] Phase 2 hoàn thành. %d lỗ hổng", len(result.vuln_data.vulnerabilities))
        except Exception as exc:
            logger.error("[COORDINATOR] Phase 2 lỗi: %s\n%s", exc, traceback.format_exc())
            from models.scan_result import VulnData
            result.vuln_data = VulnData()

        # ══════════════════════════════════════════════════════════
        # PHASE 3: REPORT GENERATION
        # ══════════════════════════════════════════════════════════
        self._update(92, "Phase 3: Tạo báo cáo", "Gemini AI đang phân tích và viết báo cáo…")
        try:
            report_agent = ReportAgent(
                progress_callback=lambda p, m: self._update(p, "Phase 3: Tạo báo cáo", m)
            )
            html_report, md_report = report_agent.run(target_url, result.recon_data, result.vuln_data)
            result.report_html     = html_report
            result.report_markdown = md_report
            self._update(99, "Phase 3: Hoàn thành", "✓ Báo cáo đã được tạo")
            logger.info("[COORDINATOR] Phase 3 hoàn thành")
        except Exception as exc:
            logger.error("[COORDINATOR] Phase 3 lỗi: %s\n%s", exc, traceback.format_exc())
            result.report_html = f"<p>Lỗi tạo báo cáo: {exc}</p>"

        # ── Kết thúc ───────────────────────────────────────────────
        result.status      = "completed"
        result.progress    = 100
        result.phase       = "Hoàn thành"
        result.finished_at = datetime.now()

        duration = (result.finished_at - result.started_at).total_seconds()
        logger.info("[COORDINATOR] Pipeline hoàn tất trong %.1fs", duration)
        self._update(100, "Hoàn thành", f"✅ Kiểm thử hoàn tất trong {duration:.1f} giây!")

        return result
