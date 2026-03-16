"""
utils/logger.py
Cấu hình logging tập trung cho toàn bộ hệ thống.
"""
import logging
import os
import sys
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Định dạng log
# ─────────────────────────────────────────────────────────────
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Thư mục lưu file log
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """
    Trả về logger có tên `name`.
    - Console handler: WARNING trở lên
    - File handler   : DEBUG trở lên (ghi vào logs/pentest_YYYY-MM-DD.log)
    """
    logger = logging.getLogger(name)

    # Tránh thêm handler trùng lặp nếu gọi nhiều lần
    if logger.handlers:
        return logger

    logger.setLevel(level)
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # ── Handler console ──────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # ── Handler file ─────────────────────────────────────────
    log_filename = os.path.join(
        LOG_DIR,
        f"pentest_{datetime.now().strftime('%Y-%m-%d')}.log"
    )
    file_handler = logging.FileHandler(log_filename, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


# Logger mặc định cho các module không tự tạo
app_logger = get_logger("pentest_ai")
