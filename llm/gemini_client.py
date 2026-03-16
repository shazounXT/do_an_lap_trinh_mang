"""
llm/gemini_client.py
Client tương tác với Groq API (OpenAI-compatible).
Model mặc định: llama-3.3-70b-versatile

Chức năng:
  - generate_pentest_report(): Tạo báo cáo pentest từ dữ liệu scan
  - analyze_vulnerabilities(): Phân tích và đánh giá lỗ hổng
"""
import json
import os
import time
from typing import Any, Dict

from openai import OpenAI

from utils.logger import get_logger

logger = get_logger("llm.groq")

# ─────────────────────────────────────────────────────────────
# Cấu hình Groq
# ─────────────────────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

_client = OpenAI(api_key=GROQ_API_KEY, base_url=GROQ_BASE_URL)


# ─────────────────────────────────────────────────────────────
# Tiện ích
# ─────────────────────────────────────────────────────────────

def _call_groq(prompt: str, max_retries: int = 3) -> str:
    """
    Gọi Groq API với cơ chế thử lại khi gặp lỗi.
    Trả về chuỗi text output.
    """
    if not GROQ_API_KEY:
        return "[LỖI] Chưa cấu hình GROQ_API_KEY."

    for attempt in range(1, max_retries + 1):
        try:
            response = _client.chat.completions.create(
                model=MODEL,
                temperature=0.3,
                max_tokens=4096,
                messages=[
                    {
                        "role": "system",
                        "content": "Bạn là chuyên gia bảo mật ứng dụng web. Trả lời tiếng Việt, rõ ràng, có cấu trúc.",
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            text = (response.choices[0].message.content or "").strip()
            logger.info("[GROQ] Thành công sau %d lần thử", attempt)
            return text
        except Exception as e:
            logger.warning("[GROQ] Lần thử %d/%d thất bại: %s", attempt, max_retries, e)
            if attempt < max_retries:
                time.sleep(2 ** attempt)  # Exponential backoff
    return "[LỖI] Không thể kết nối Groq API sau nhiều lần thử."


# ─────────────────────────────────────────────────────────────
# 1. Tạo báo cáo Pentest
# ─────────────────────────────────────────────────────────────

_REPORT_PROMPT_TEMPLATE = """
Bạn là một chuyên gia bảo mật thông tin (Penetration Tester) cấp cao.
Hãy phân tích dữ liệu kiểm thử bảo mật bên dưới và tạo một báo cáo pentest
chuyên nghiệp, chi tiết bằng tiếng Việt.

## DỮ LIỆU KIỂM THỬ

### Thông tin mục tiêu
- URL: {target_url}
- Hostname: {hostname}
- Địa chỉ IP: {ip_addresses}

### Kết quả Reconnaissance
- **Cổng mở:** {open_ports}
- **Subdomain tìm thấy:** {subdomains}
- **DNS Records:** {dns_records}
- **Thông tin server:** {server_info}

### Lỗ hổng bảo mật phát hiện
{vulnerabilities_detail}

### Kiểm tra Security Headers
- Điểm số: {header_score}/100 (Hạng: {header_grade})
- Headers thiếu: {missing_headers}
- Headers có sẵn: {present_headers}

### Cookie Security
{cookie_info}

---

## YÊU CẦU BÁO CÁO

Hãy tạo báo cáo theo cấu trúc sau:

# BÁO CÁO KIỂM THỬ BẢO MẬT
**Tài liệu bảo mật nội bộ – Không phân phối bên ngoài**

## 1. TÓM TẮT ĐIỀU HÀNH
Tóm tắt ngắn gọn (3-5 dòng) về kết quả tổng thể, mức độ rủi ro tổng thể.

## 2. PHẠM VI KIỂM THỬ
Mô tả mục tiêu và phạm vi kiểm thử.

## 3. PHƯƠNG PHÁP KIỂM THỬ
Mô tả các bước và kỹ thuật đã sử dụng.

## 4. THÔNG TIN HỆ THỐNG MỤC TIÊU
Bảng thông tin kỹ thuật về mục tiêu.

## 5. LỖ HỔNG BẢO MẬT
Với mỗi lỗ hổng, hãy mô tả:
- Tên lỗ hổng và mức độ nghiêm trọng (Critical/High/Medium/Low)
- Mô tả kỹ thuật
- Bằng chứng / Bước tái hiện
- Tác động (Impact)
- Khuyến nghị khắc phục (Remediation)

## 6. PHÂN TÍCH RỦI RO
Ma trận rủi ro và đánh giá tổng thể.

## 7. KHUYẾN NGHỊ ƯU TIÊN
Liệt kê các hành động khắc phục theo thứ tự ưu tiên.

## 8. KẾT LUẬN
Nhận xét tổng kết.

---
Lưu ý: Sử dụng Markdown formatting. Nghiêm túc, chuyên nghiệp, dựa trên bằng chứng thực tế từ dữ liệu.
"""


def generate_pentest_report(scan_data: Dict[str, Any]) -> str:
    """
    Tạo báo cáo pentest hoàn chỉnh từ dữ liệu scan.

    Args:
        scan_data: Dict chứa recon_data và vuln_data

    Returns:
        Báo cáo Markdown định dạng chuyên nghiệp
    """
    logger.info("[GROQ] Bắt đầu tạo báo cáo pentest")

    recon = scan_data.get("recon_data", {})
    vuln  = scan_data.get("vuln_data", {})

    # Chuẩn bị thông tin lỗ hổng
    vuln_list = vuln.get("vulnerabilities", [])
    if vuln_list:
        vuln_detail_lines = []
        for v in vuln_list:
            vuln_detail_lines.append(
                f"- **{v['name']}** [{v['severity'].upper()}]\n"
                f"  * Mô tả: {v['description']}\n"
                f"  * Bằng chứng: {v.get('evidence', 'N/A')}\n"
                f"  * Khuyến nghị: {v.get('recommendation', 'N/A')}"
            )
        vulnerabilities_detail = "\n".join(vuln_detail_lines)
    else:
        vulnerabilities_detail = "Không phát hiện lỗ hổng nghiêm trọng."

    # Thông tin cookie
    cookie_data = vuln.get("security_headers", {}).get("cookies", {})
    insecure_cookies = cookie_data.get("insecure", []) if isinstance(cookie_data, dict) else []
    if insecure_cookies:
        cookie_info = f"Phát hiện {len(insecure_cookies)} cookie thiếu cờ bảo mật (Secure/HttpOnly)"
    else:
        cookie_info = "Không phát hiện vấn đề cookie"

    # Thông tin headers
    header_info = vuln.get("security_headers", {}).get("headers", {})
    header_score   = header_info.get("score", 0) if isinstance(header_info, dict) else 0
    header_grade   = header_info.get("grade", "?") if isinstance(header_info, dict) else "?"
    missing_headers = ", ".join(header_info.get("missing", [])) if isinstance(header_info, dict) else "N/A"
    present_headers = ", ".join(header_info.get("present", {}).keys()) if isinstance(header_info, dict) else "N/A"

    # Format open ports
    ports_str = ", ".join(
        f"{p['port']}/{p['service']}"
        for p in recon.get("open_ports", [])
    ) or "Không tìm thấy"

    prompt = _REPORT_PROMPT_TEMPLATE.format(
        target_url=recon.get("target_url", scan_data.get("target_url", "?")),
        hostname=recon.get("hostname", "?"),
        ip_addresses=", ".join(recon.get("ip_addresses", [])) or "Không xác định",
        open_ports=ports_str,
        subdomains=", ".join(recon.get("subdomains", [])[:10]) or "Không tìm thấy",
        dns_records=json.dumps(recon.get("dns_records", {}), ensure_ascii=False),
        server_info=recon.get("server_info", "Không rõ"),
        vulnerabilities_detail=vulnerabilities_detail,
        header_score=header_score,
        header_grade=header_grade,
        missing_headers=missing_headers or "Không có",
        present_headers=present_headers or "Không có",
        cookie_info=cookie_info,
    )

    report = _call_groq(prompt)
    logger.info("[GROQ] Báo cáo hoàn thành (%d ký tự)", len(report))
    return report


# ─────────────────────────────────────────────────────────────
# 2. Phân tích nhanh lỗ hổng
# ─────────────────────────────────────────────────────────────

def analyze_vulnerabilities(findings: Dict[str, Any]) -> str:
    """
    Phân tích nhanh một tập hợp phát hiện lỗ hổng.
    Trả về đánh giá ngắn gọn bằng tiếng Việt.
    """
    prompt = (
        "Hãy đánh giá ngắn gọn (100-150 từ) bằng tiếng Việt về các lỗ hổng sau:\n\n"
        + json.dumps(findings, ensure_ascii=False, indent=2)
        + "\n\nChỉ ra mức độ rủi ro tổng thể và ưu tiên khắc phục."
    )
    return _call_groq(prompt)
