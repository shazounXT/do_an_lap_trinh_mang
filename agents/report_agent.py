"""
agents/report_agent.py
ReportAgent – Tổng hợp dữ liệu và tạo báo cáo pentest bằng Gemini API.

Công việc:
  1. Nhận recon_data + vuln_data từ các agent trước
  2. Gọi Gemini API để tạo báo cáo Markdown chuyên nghiệp
  3. Convert Markdown → HTML để hiển thị trên web
"""
import html
import re
from typing import Callable

from models.scan_result import ReconData, VulnData
from utils.logger import get_logger

logger = get_logger("agent.report")


class ReportAgent:
    """
    Agent tạo báo cáo pentest chuyên nghiệp sử dụng Gemini LLM.
    """

    def __init__(self, progress_callback: Callable[[int, str], None] | None = None):
        self._progress = progress_callback or (lambda p, m: None)

    def _update(self, pct: int, msg: str) -> None:
        logger.info("[REPORT] %d%% – %s", pct, msg)
        self._progress(pct, msg)

    @staticmethod
    def _markdown_to_html(md: str) -> str:
        """
        Chuyển đổi Markdown cơ bản sang HTML.
        Hỗ trợ: headings, bold, italic, lists, code blocks, horizontal rules.
        """
        # Escape HTML đặc biệt trước (ngoại trừ markdown syntax)
        lines = md.split("\n")
        html_parts = []
        in_code_block   = False
        in_ul           = False
        in_ol           = False

        for line in lines:
            # ── Code block ─────────────────────────────────────────
            if line.strip().startswith("```"):
                if not in_code_block:
                    if in_ul:
                        html_parts.append("</ul>"); in_ul = False
                    if in_ol:
                        html_parts.append("</ol>"); in_ol = False
                    html_parts.append('<pre><code>')
                    in_code_block = True
                else:
                    html_parts.append('</code></pre>')
                    in_code_block = False
                continue

            if in_code_block:
                html_parts.append(html.escape(line))
                continue

            # ── Headings ──────────────────────────────────────────
            heading_match = re.match(r'^(#{1,6})\s+(.*)', line)
            if heading_match:
                if in_ul: html_parts.append("</ul>"); in_ul = False
                if in_ol: html_parts.append("</ol>"); in_ol = False
                level = len(heading_match.group(1))
                text  = heading_match.group(2)
                text  = ReportAgent._inline_format(text)
                html_parts.append(f'<h{level}>{text}</h{level}>')
                continue

            # ── Horizontal rule ───────────────────────────────────
            if re.match(r'^[-*_]{3,}$', line.strip()):
                if in_ul: html_parts.append("</ul>"); in_ul = False
                if in_ol: html_parts.append("</ol>"); in_ol = False
                html_parts.append('<hr>')
                continue

            # ── Unordered list ────────────────────────────────────
            ul_match = re.match(r'^(\s*)[*\-•]\s+(.*)', line)
            if ul_match:
                if in_ol: html_parts.append("</ol>"); in_ol = False
                if not in_ul:
                    html_parts.append('<ul>')
                    in_ul = True
                item = ReportAgent._inline_format(ul_match.group(2))
                html_parts.append(f'<li>{item}</li>')
                continue

            # ── Ordered list ──────────────────────────────────────
            ol_match = re.match(r'^\s*\d+\.\s+(.*)', line)
            if ol_match:
                if in_ul: html_parts.append("</ul>"); in_ul = False
                if not in_ol:
                    html_parts.append('<ol>')
                    in_ol = True
                item = ReportAgent._inline_format(ol_match.group(1))
                html_parts.append(f'<li>{item}</li>')
                continue

            # ── Empty line → close lists / paragraph break ────────
            if not line.strip():
                if in_ul: html_parts.append("</ul>"); in_ul = False
                if in_ol: html_parts.append("</ol>"); in_ol = False
                html_parts.append('<br>')
                continue

            # ── Regular paragraph ─────────────────────────────────
            if in_ul: html_parts.append("</ul>"); in_ul = False
            if in_ol: html_parts.append("</ol>"); in_ol = False
            html_parts.append(f'<p>{ReportAgent._inline_format(line)}</p>')

        if in_ul: html_parts.append("</ul>")
        if in_ol: html_parts.append("</ol>")

        return "\n".join(html_parts)

    @staticmethod
    def _inline_format(text: str) -> str:
        """Xử lý inline Markdown: bold, italic, inline code."""
        # Inline code
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        # Bold
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'__(.+?)__',     r'<strong>\1</strong>', text)
        # Italic
        text = re.sub(r'\*(.+?)\*',     r'<em>\1</em>',  text)
        text = re.sub(r'_(.+?)_',       r'<em>\1</em>',  text)
        return text

    def run(self, target_url: str, recon_data: ReconData, vuln_data: VulnData) -> str:
        """
        Tạo báo cáo pentest bằng Gemini API.

        Args:
            target_url : URL mục tiêu
            recon_data : Kết quả Reconnaissance
            vuln_data  : Kết quả đánh giá lỗ hổng

        Returns:
            Báo cáo dạng HTML string để nhúng vào trang kết quả.
        """
        logger.info("[REPORT] Bắt đầu tạo báo cáo cho: %s", target_url)
        self._update(92, "Đang phân tích dữ liệu với Gemini AI…")

        # ── Chuẩn bị dữ liệu để truyền vào Gemini ─────────────────
        scan_payload = {
            "target_url": target_url,
            "recon_data": {
                "target_url":   recon_data.target_url,
                "hostname":     recon_data.hostname,
                "ip_addresses": recon_data.ip_addresses,
                "open_ports":   recon_data.open_ports,
                "subdomains":   recon_data.subdomains,
                "dns_records":  recon_data.dns_records,
                "server_info":  recon_data.server_info,
            },
            "vuln_data": {
                "vulnerabilities": [
                    {
                        "name":           v.name,
                        "severity":       v.severity,
                        "description":    v.description,
                        "evidence":       v.evidence,
                        "recommendation": v.recommendation,
                    }
                    for v in vuln_data.vulnerabilities
                ],
                "security_headers": vuln_data.security_headers,
            },
        }

        # ── Gọi Gemini ─────────────────────────────────────────────
        try:
            from llm.gemini_client import generate_pentest_report
            self._update(95, "Gemini đang viết báo cáo…")
            markdown_report = generate_pentest_report(scan_payload)
        except Exception as exc:
            logger.error("[REPORT] Gemini lỗi: %s", exc)
            # Tạo báo cáo fallback nếu Gemini không hoạt động
            markdown_report = self._fallback_report(target_url, recon_data, vuln_data)

        # ── Convert sang HTML ──────────────────────────────────────
        self._update(98, "Hoàn chỉnh báo cáo…")
        html_report = self._markdown_to_html(markdown_report)

        logger.info("[REPORT] Báo cáo hoàn thành (%d ký tự)", len(html_report))
        return html_report, markdown_report

    def _fallback_report(self, target_url: str, recon: ReconData, vuln: VulnData) -> str:
        """Báo cáo cơ bản khi Gemini API không khả dụng."""
        vuln_lines = "\n".join(
            f"- **{v.name}** [{v.severity.upper()}]: {v.description}"
            for v in vuln.vulnerabilities
        ) or "- Không phát hiện lỗ hổng nghiêm trọng"

        ports_str = ", ".join(
            f"{p['port']}/{p['service']}" for p in recon.open_ports
        ) or "Không tìm thấy"

        return f"""# BÁO CÁO KIỂM THỬ BẢO MẬT

**Lưu ý:** Báo cáo được tạo tự động (Gemini API không khả dụng)

---

## 1. THÔNG TIN MỤC TIÊU

- **URL:** {target_url}
- **Hostname:** {recon.hostname}
- **IP:** {', '.join(recon.ip_addresses) or 'Không xác định'}
- **Server:** {recon.server_info}

## 2. CỔNG MỞ

{ports_str}

## 3. SUBDOMAIN ({len(recon.subdomains)} tìm thấy)

{chr(10).join('- ' + s for s in recon.subdomains[:15]) or '- Không tìm thấy'}

## 4. LỖ HỔNG BẢO MẬT ({len(vuln.vulnerabilities)} phát hiện)

{vuln_lines}

## 5. MỨC ĐỘ RỦI RO TỔNG THỂ: {vuln.risk_level.upper()}

## 6. KHUYẾN NGHỊ

Vui lòng xem xét từng lỗ hổng được liệt kê và thực hiện các biện pháp khắc phục tương ứng.
Ưu tiên xử lý các lỗ hổng Critical và High trước.

---
*Báo cáo được tạo bởi PentestAI Multi-Agent System*
"""
