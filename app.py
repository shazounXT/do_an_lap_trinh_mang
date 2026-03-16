"""
app.py
Flask application chính – Hệ thống Multi-Agent Pentest AI.

Routes:
  GET  /               → Trang chủ (nhập URL)
  POST /scan           → Bắt đầu scan, trả về scan_id
  GET  /result/<id>    → Trang hiển thị kết quả
  GET  /api/status/<id>→ API kiểm tra tiến trình (JSON)
  GET  /api/result/<id>→ API lấy kết quả đầy đủ (JSON)

Scan chạy bất đồng bộ trong background thread.
Poll mỗi 2s để cập nhật progress bar.
"""
import ipaddress
import os
import re
import socket
import threading
import urllib.parse
import uuid
from datetime import datetime

from flask import Flask, jsonify, redirect, render_template, request, url_for

from agents.coordinator_agent import CoordinatorAgent
from models.scan_result import ScanResult
from utils.logger import get_logger

# ─────────────────────────────────────────────────────────────
# Khởi tạo Flask
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)

logger = get_logger("app")

# ─────────────────────────────────────────────────────────────
# Kho lưu trữ kết quả scan (in-memory, đủ dùng cho demo)
# ─────────────────────────────────────────────────────────────
scan_store: dict[str, ScanResult] = {}
store_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────
# Bảo mật: Kiểm tra URL đầu vào
# ─────────────────────────────────────────────────────────────

BLOCKED_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Danh sách trắng các domain được phép test (lab environment)
ALLOWED_DEMO_DOMAINS = {
    "testphp.vulnweb.com",
    "zero.webappsecurity.com",
    "demo.testfire.net",
    "juice-shop.herokuapp.com",
    "dvwa.co.uk",
    "webscantest.com",
    "scanme.nmap.org",
    "hackthissite.org",
    "vulnweb.com",
}


def _is_safe_target(url: str) -> tuple[bool, str]:
    """
    Kiểm tra URL có an toàn để scan không.
    Ngăn chặn SSRF vào địa chỉ nội bộ / hệ thống.

    Returns:
        (True, "") nếu an toàn
        (False, lý_do) nếu không an toàn
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "URL không hợp lệ"

    if parsed.scheme not in ("http", "https"):
        return False, "Chỉ chấp nhận http:// hoặc https://"

    hostname = parsed.hostname or ""
    if not hostname:
        return False, "Không thể xác định hostname"

    # Ngăn chặn truy cập file:// và các scheme nguy hiểm
    if re.search(r'[<>"\']', hostname):
        return False, "Hostname chứa ký tự không hợp lệ"

    # Chặn IP nội bộ (SSRF prevention)
    try:
        ip = ipaddress.ip_address(hostname)
        for block in BLOCKED_PRIVATE_RANGES:
            if ip in block:
                return False, f"Không được phép scan địa chỉ IP nội bộ: {hostname}"
    except ValueError:
        # Không phải IP → kiểm tra tên miền
        if hostname in ("localhost", "metadata.google.internal"):
            return False, f"Không được phép scan: {hostname}"

    return True, ""


def _normalize_url(url: str) -> str:
    """Chuẩn hóa URL: thêm https:// nếu thiếu scheme."""
    url = url.strip()
    if not re.match(r'^https?://', url):
        url = "http://" + url
    return url.rstrip("/")


# ─────────────────────────────────────────────────────────────
# Background scan runner
# ─────────────────────────────────────────────────────────────

def _run_scan_background(scan_id: str, target_url: str) -> None:
    """Chạy pipeline scan trong background thread."""
    with store_lock:
        result = scan_store.get(scan_id)
    if not result:
        return

    def progress_callback(pct: int, msg: str) -> None:
        """Cập nhật tiến trình vào scan_store."""
        with store_lock:
            r = scan_store.get(scan_id)
            if r:
                r.progress = pct
                r.phase    = msg

    try:
        coordinator = CoordinatorAgent(result, progress_callback)
        coordinator.run()
    except Exception as exc:
        logger.error("[APP] Scan %s thất bại: %s", scan_id, exc)
        with store_lock:
            r = scan_store.get(scan_id)
            if r:
                r.status        = "error"
                r.error_message = str(exc)
                r.finished_at   = datetime.now()


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Trang chủ – Form nhập URL kiểm thử."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan():
    """
    Nhận URL từ form, tạo scan_id mới, chạy scan trong background.
    Redirect đến trang kết quả.
    """
    raw_url = request.form.get("target_url", "").strip()
    if not raw_url:
        return render_template("index.html", error="Vui lòng nhập URL cần kiểm thử.")

    target_url = _normalize_url(raw_url)

    # Kiểm tra bảo mật URL
    safe, reason = _is_safe_target(target_url)
    if not safe:
        logger.warning("[APP] URL bị từ chối: %s – %s", target_url, reason)
        return render_template("index.html", error=f"URL không được phép: {reason}")

    # Tạo scan_id và khởi tạo ScanResult
    scan_id = str(uuid.uuid4())[:8]
    result  = ScanResult(
        scan_id=scan_id,
        target_url=target_url,
        status="pending",
        phase="Đang chuẩn bị…",
        progress=0,
    )

    with store_lock:
        scan_store[scan_id] = result

    # Khởi chạy scan trong thread riêng
    thread = threading.Thread(
        target=_run_scan_background,
        args=(scan_id, target_url),
        daemon=True,
        name=f"scan-{scan_id}",
    )
    thread.start()
    logger.info("[APP] Scan %s bắt đầu cho: %s", scan_id, target_url)

    return redirect(url_for("result_page", scan_id=scan_id))


@app.route("/result/<scan_id>", methods=["GET"])
def result_page(scan_id: str):
    """Trang kết quả – hiển thị tiến trình và kết quả sau khi Hoàn thành."""
    with store_lock:
        result = scan_store.get(scan_id)

    if not result:
        return render_template("index.html", error=f"Không tìm thấy scan ID: {scan_id}"), 404

    return render_template("result.html", scan=result.to_dict(), scan_id=scan_id)


@app.route("/api/status/<scan_id>", methods=["GET"])
def api_status(scan_id: str):
    """
    API endpoint trả về trạng thái scan hiện tại.
    Frontend dùng để poll mỗi 2 giây.
    """
    with store_lock:
        result = scan_store.get(scan_id)

    if not result:
        return jsonify({"error": "Scan không tồn tại"}), 404

    return jsonify({
        "scan_id":  scan_id,
        "status":   result.status,
        "phase":    result.phase,
        "progress": result.progress,
        "error":    result.error_message,
    })


@app.route("/api/result/<scan_id>", methods=["GET"])
def api_result(scan_id: str):
    """
    API endpoint trả về kết quả scan đầy đủ (JSON).
    Chỉ hợp lệ khi scan đã completed.
    """
    with store_lock:
        result = scan_store.get(scan_id)

    if not result:
        return jsonify({"error": "Scan không tồn tại"}), 404

    if result.status not in ("completed", "error"):
        return jsonify({"error": "Scan chưa hoàn thành", "status": result.status}), 202

    return jsonify(result.to_dict())


@app.route("/api/scans", methods=["GET"])
def api_list_scans():
    """API liệt kê tất cả các scan (debug endpoint)."""
    with store_lock:
        scans = [
            {
                "scan_id":    sid,
                "target_url": r.target_url,
                "status":     r.status,
                "progress":   r.progress,
                "started_at": r.started_at.isoformat() if r.started_at else None,
            }
            for sid, r in scan_store.items()
        ]
    return jsonify(scans)


# ─────────────────────────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("index.html", error="Trang không tồn tại (404)."), 404


@app.errorhandler(500)
def server_error(e):
    logger.error("[APP] Lỗi server: %s", e)
    return render_template("index.html", error="Lỗi máy chủ nội bộ (500)."), 500


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _get_local_ip() -> str:
    """Lấy địa chỉ IP thật của máy để hiển thị link truy cập nội bộ."""
    try:
        # Kết nối UDP (không gửi dữ liệu) giúp xác định IP mặc định của máy.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    local_ip = _get_local_ip()
    logger.info("=" * 60)
    logger.info("  PentestAI Multi-Agent System đang khởi động...")
    logger.info("  Truy cập: http://localhost:8080")
    logger.info("  Truy cập (LAN): http://%s:8080", local_ip)
    logger.info("=" * 60)

    # Debug: in case the terminal isn't showing flask output.
    print("[APP] Starting Flask server on 0.0.0.0:8080", flush=True)

    try:
        app.run(
            host="0.0.0.0",
            port=8080,
            debug=True,
            use_reloader=False,   # Tắt reloader để tránh chạy 2 lần khi dev
        )
    except Exception as e:
        # If binding fails (port in use / permission), log it clearly so user can see.
        logger.exception("[APP] Không thể khởi động Flask server")
        print(f"[APP] Lỗi khi khởi động server: {e}", flush=True)
        raise
