"""
toolkit/vuln_scan_tools.py
Công cụ phát hiện lỗ hổng bảo mật cơ bản trên web application.

Các kiểm tra bao gồm:
  1. check_security_headers()  – Kiểm tra HTTP security headers
  2. check_sql_injection()     – Thử các payload SQL cơ bản
  3. check_xss()               – Thử các payload XSS cơ bản
  4. check_server_info()       – Lấy thông tin server / outdated version
  5. check_sensitive_paths()   – Kiểm tra đường dẫn nhạy cảm
  6. check_cookie_flags()      – Kiểm tra thuộc tính cookie (Secure, HttpOnly)

CẢNH BÁO: Chỉ sử dụng trên hệ thống được phép kiểm thử!
"""
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Tuple

from utils.logger import get_logger

logger = get_logger("toolkit.vuln")

# Timeout mặc định cho mọi HTTP request (giây)
HTTP_TIMEOUT = 8

# User-Agent báo rõ đây là công cụ kiểm thử
HEADERS = {
    "User-Agent": "PentestAI-Scanner/1.0 (Authorized Security Testing)",
    "Accept":     "text/html,application/xhtml+xml,*/*",
}


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _fetch(url: str, extra_headers: Dict[str, str] | None = None) -> Tuple[int, str, Dict]:
    """
    Thực hiện HTTP GET.
    Trả về (status_code, body_text, response_headers).
    Trả về (-1, "", {}) nếu có lỗi.
    """
    req = urllib.request.Request(url, headers={**HEADERS, **(extra_headers or {})})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            body = resp.read(32_768).decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            return resp.status, body, headers
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode("utf-8", errors="replace")
        return e.code, body, dict(e.headers)
    except Exception as exc:
        logger.debug("[VULN] Lỗi fetch %s: %s", url, exc)
        return -1, "", {}


# ─────────────────────────────────────────────────────────────
# 1. Security Headers
# ─────────────────────────────────────────────────────────────

REQUIRED_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security":  "Bảo vệ HTTPS (HSTS)",
    "Content-Security-Policy":    "Ngăn chặn XSS/injection",
    "X-Frame-Options":            "Ngăn chặn Clickjacking",
    "X-Content-Type-Options":     "Ngăn chặn MIME sniffing",
    "Referrer-Policy":            "Kiểm soát thông tin Referrer",
    "Permissions-Policy":         "Kiểm soát quyền truy cập tài nguyên",
    "X-XSS-Protection":           "Bộ lọc XSS của trình duyệt",
}


def check_security_headers(url: str) -> Dict[str, Any]:
    """
    Kiểm tra các HTTP security header bắt buộc.
    Trả về dict gồm header hiện có, thiếu, và điểm tổng thể.
    """
    logger.info("[VULN] Kiểm tra security headers: %s", url)
    status, _, resp_headers = _fetch(url)

    if status == -1:
        return {"error": "Không thể kết nối tới URL", "present": {}, "missing": []}

    present: Dict[str, str] = {}
    missing: List[str] = []

    for header, description in REQUIRED_HEADERS.items():
        # Headers không phân biệt hoa thường
        found_val = next(
            (v for k, v in resp_headers.items() if k.lower() == header.lower()),
            None,
        )
        if found_val:
            present[header] = found_val
        else:
            missing.append(f"{header} ({description})")

    score = int((len(present) / len(REQUIRED_HEADERS)) * 100)
    logger.debug("[VULN] Headers – có: %d, thiếu: %d", len(present), len(missing))
    return {
        "present": present,
        "missing": missing,
        "score":   score,
        "grade":   "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "F",
    }


# ─────────────────────────────────────────────────────────────
# 2. SQL Injection
# ─────────────────────────────────────────────────────────────

SQL_PAYLOADS: List[str] = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' AND 1=2 UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "1 OR 1=1",
    "admin'--",
]

SQL_ERROR_PATTERNS: List[str] = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"syntax error.*sql",
    r"ora-\d{4,5}:",
    r"microsoft sql server",
    r"postgresql.*error",
    r"sqlite.*exception",
    r"jdbc.*exception",
    r"mysql_fetch",
    r"pg_query\(\)",
    r"odbc.*error",
]


def check_sql_injection(url: str) -> Dict[str, Any]:
    """
    Thử các payload SQL Injection vào các tham số URL.
    Phát hiện dựa trên thông báo lỗi DB trong response.
    """
    logger.info("[VULN] Kiểm tra SQL Injection: %s", url)
    findings: List[Dict[str, str]] = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    # Nếu không có tham số, thêm tham số giả để test
    if not params:
        params = {"id": ["1"], "q": ["test"], "search": ["test"]}

    for param_name in params:
        # Chỉ test 2 payload đầu để tránh quá chậm
        for payload in SQL_PAYLOADS[:4]:
            new_params = dict(params)
            new_params[param_name] = [payload]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            _, body, _ = _fetch(test_url)
            body_lower = body.lower()

            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, body_lower):
                    finding = {
                        "param":   param_name,
                        "payload": payload,
                        "pattern": pattern,
                        "url":     test_url,
                    }
                    findings.append(finding)
                    logger.warning("[VULN] SQLi tìm thấy: param=%s", param_name)
                    break

    return {
        "vulnerable":   len(findings) > 0,
        "findings":     findings,
        "tested_params": list(params.keys()),
    }


# ─────────────────────────────────────────────────────────────
# 3. Cross-Site Scripting (XSS)
# ─────────────────────────────────────────────────────────────

XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert('xss')</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]


def check_xss(url: str) -> Dict[str, Any]:
    """
    Thử các payload XSS cơ bản, kiểm tra xem payload có bị phản chiếu trong response không.
    """
    logger.info("[VULN] Kiểm tra XSS: %s", url)
    findings: List[Dict[str, str]] = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        params = {"q": ["test"], "search": ["test"], "name": ["test"]}

    for param_name in params:
        for payload in XSS_PAYLOADS[:3]:
            new_params = dict(params)
            new_params[param_name] = [payload]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            _, body, _ = _fetch(test_url)

            # Kiểm tra payload có xuất hiện trong response mà không bị encode không
            if payload in body or payload.lower() in body.lower():
                findings.append({
                    "param":   param_name,
                    "payload": payload,
                    "url":     test_url,
                })
                logger.warning("[VULN] XSS phản chiếu tìm thấy: param=%s", param_name)

    return {
        "vulnerable": len(findings) > 0,
        "findings":   findings,
    }


# ─────────────────────────────────────────────────────────────
# 4. Server Info & Outdated Software
# ─────────────────────────────────────────────────────────────

OUTDATED_PATTERNS: Dict[str, str] = {
    r"apache/([12]\.\d+)":         "Apache (có thể lỗi thời)",
    r"nginx/([01]\.\d+)":          "Nginx (có thể lỗi thời)",
    r"php/([45]\.\d+)":            "PHP 4/5 (đã hết hỗ trợ)",
    r"iis/([0-9]\.\d+)":           "IIS (kiểm tra phiên bản)",
    r"tomcat/([0-8]\.\d+)":        "Tomcat (có thể lỗi thời)",
    r"wordpress/([0-5]\.\d+)":     "WordPress cũ",
    r"joomla[!/]([0-3]\.\d+)":     "Joomla cũ",
    r"drupal[/ ]([0-8]\.\d+)":     "Drupal cũ",
}


def check_server_info(url: str) -> Dict[str, Any]:
    """
    Lấy thông tin server từ HTTP response headers và body.
    Phát hiện phần mềm lỗi thời.
    """
    logger.info("[VULN] Lấy thông tin server: %s", url)
    status, body, headers = _fetch(url)

    if status == -1:
        return {"error": "Không thể kết nối"}

    server_header = headers.get("Server", headers.get("server", "Không rõ"))
    x_powered_by  = headers.get("X-Powered-By", headers.get("x-powered-by", ""))

    disclosed: List[str] = []
    all_info = f"{server_header} {x_powered_by} {body[:2000]}".lower()

    for pattern, description in OUTDATED_PATTERNS.items():
        m = re.search(pattern, all_info, re.IGNORECASE)
        if m:
            disclosed.append(f"{description} – phiên bản {m.group(1)}")

    return {
        "server_header": server_header,
        "x_powered_by":  x_powered_by,
        "status_code":   status,
        "disclosed_info": disclosed,
        "info_disclosed": bool(server_header and server_header != "Không rõ"),
    }


# ─────────────────────────────────────────────────────────────
# 5. Sensitive Paths
# ─────────────────────────────────────────────────────────────

SENSITIVE_PATHS: List[Tuple[str, str]] = [
    ("/admin",           "Trang quản trị"),
    ("/administrator",   "Trang quản trị Joomla"),
    ("/wp-admin",        "Trang quản trị WordPress"),
    ("/wp-login.php",    "Trang đăng nhập WordPress"),
    ("/.env",            "File cấu hình môi trường"),
    ("/.git",            "Thư mục Git (lộ source code)"),
    ("/config.php",      "File cấu hình PHP"),
    ("/phpinfo.php",     "PHP Info (lộ thông tin server)"),
    ("/phpmyadmin",      "phpMyAdmin"),
    ("/backup",          "Thư mục backup"),
    ("/backup.zip",      "File backup"),
    ("/db.sql",          "File database dump"),
    ("/robots.txt",      "Robots.txt (thông tin cấu trúc site)"),
    ("/sitemap.xml",     "Sitemap XML"),
    ("/crossdomain.xml", "Cross-domain policy"),
    ("/server-status",   "Apache server-status"),
    ("/info.php",        "PHP Info"),
    ("/.htaccess",       "File .htaccess"),
]


def check_sensitive_paths(base_url: str) -> Dict[str, Any]:
    """
    Kiểm tra sự tồn tại của các đường dẫn nhạy cảm trên website.
    Chỉ phát hiện các đường dẫn trả về HTTP 200.
    """
    logger.info("[VULN] Kiểm tra sensitive paths: %s", base_url)
    base_url = base_url.rstrip("/")
    found: List[Dict[str, str]] = []

    for path, description in SENSITIVE_PATHS:
        test_url = base_url + path
        status, _, _ = _fetch(test_url)
        if status == 200:
            found.append({
                "path":        path,
                "full_url":    test_url,
                "description": description,
            })
            logger.warning("[VULN] Đường dẫn nhạy cảm: %s (%s)", test_url, description)
        time.sleep(0.05)  # Hạn chế tốc độ request

    return {
        "found_paths": found,
        "count":       len(found),
    }


# ─────────────────────────────────────────────────────────────
# 6. Cookie Flags
# ─────────────────────────────────────────────────────────────

def check_cookie_flags(url: str) -> Dict[str, Any]:
    """
    Kiểm tra cookie có đặt đúng các flag bảo mật:
    Secure, HttpOnly, SameSite.
    """
    logger.info("[VULN] Kiểm tra cookie flags: %s", url)
    insecure_cookies: List[Dict[str, Any]] = []

    req = urllib.request.Request(url, headers=HEADERS)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            raw_cookies = resp.headers.get_all("Set-Cookie") or []
    except Exception as e:
        logger.debug("[VULN] Lỗi lấy cookie: %s", e)
        return {"cookies": [], "insecure": []}

    cookies_info: List[Dict[str, Any]] = []
    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name  = parts[0].split("=")[0] if parts else "?"
        flags = [p.lower() for p in parts[1:]]
        info: Dict[str, Any] = {
            "name":      name,
            "secure":    any("secure" in f for f in flags),
            "httponly":  any("httponly" in f for f in flags),
            "samesite":  next((f for f in flags if f.startswith("samesite")), None),
            "raw":       raw[:200],
        }
        cookies_info.append(info)
        if not info["secure"] or not info["httponly"]:
            insecure_cookies.append(info)

    return {
        "cookies":  cookies_info,
        "insecure": insecure_cookies,
    }
