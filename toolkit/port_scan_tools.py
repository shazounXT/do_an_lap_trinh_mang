"""
toolkit/port_scan_tools.py
Công cụ quét cổng TCP sử dụng Python socket (không cần nmap).
Quét song song để tăng tốc độ.
"""
import concurrent.futures
import socket
from typing import Any, Dict, List

from utils.logger import get_logger

logger = get_logger("toolkit.portscan")

# Danh sách cổng phổ biến cùng tên dịch vụ tương ứng
COMMON_PORTS: Dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    27017: "MongoDB",
}


def _check_port(hostname: str, port: int, timeout: float = 1.5) -> Dict[str, Any] | None:
    """
    Kiểm tra một cổng TCP.
    Trả về dict nếu cổng mở, None nếu đóng hoặc lỗi.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((hostname, port))
        if code == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            return {
                "port":    port,
                "state":   "open",
                "service": service,
            }
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def port_scan(
    hostname: str,
    ports: List[int] | None = None,
    max_workers: int = 30,
) -> List[Dict[str, Any]]:
    """
    Quét các cổng TCP trên `hostname`.

    Args:
        hostname    : Địa chỉ IP hoặc tên miền mục tiêu
        ports       : Danh sách cổng cần quét (mặc định: COMMON_PORTS)
        max_workers : Số luồng song song

    Returns:
        Danh sách dict [{port, state, service}] chỉ với các cổng MỞ,
        sắp xếp theo số cổng tăng dần.
    """
    target_ports = ports if ports is not None else list(COMMON_PORTS.keys())
    logger.info(
        "[PORTSCAN] Bắt đầu quét %d cổng trên %s",
        len(target_ports), hostname
    )

    open_ports: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_port, hostname, p): p
            for p in target_ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                logger.debug(
                    "[PORTSCAN] %s:%d OPEN (%s)",
                    hostname, result["port"], result["service"]
                )

    open_ports.sort(key=lambda x: x["port"])
    logger.info(
        "[PORTSCAN] Hoàn tất: %d cổng mở trên %s",
        len(open_ports), hostname
    )
    return open_ports
