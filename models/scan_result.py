"""
models/scan_result.py
Định nghĩa cấu trúc dữ liệu cho kết quả quét bảo mật.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class VulnerabilityItem:
    """Một lỗ hổng bảo mật được phát hiện."""
    name: str                    # Tên lỗ hổng
    severity: str                # critical / high / medium / low / info
    description: str             # Mô tả chi tiết
    evidence: str = ""           # Bằng chứng / dữ liệu thô
    recommendation: str = ""     # Khuyến nghị khắc phục


@dataclass
class ReconData:
    """Dữ liệu thu thập trong giai đoạn Reconnaissance."""
    target_url: str
    hostname: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)   # [{port, service, state}]
    subdomains: List[str] = field(default_factory=list)
    dns_records: Dict[str, Any] = field(default_factory=dict)
    server_info: str = ""
    raw_errors: List[str] = field(default_factory=list)


@dataclass
class VulnData:
    """Dữ liệu từ giai đoạn Vulnerability Assessment."""
    vulnerabilities: List[VulnerabilityItem] = field(default_factory=list)
    security_headers: Dict[str, Any] = field(default_factory=dict)
    raw_errors: List[str] = field(default_factory=list)

    # Tính toán risk level tổng thể
    @property
    def risk_level(self) -> str:
        if not self.vulnerabilities:
            return "Thấp"
        severities = [v.severity.lower() for v in self.vulnerabilities]
        if "critical" in severities:
            return "Nghiêm trọng"
        if "high" in severities:
            return "Cao"
        if "medium" in severities:
            return "Trung bình"
        return "Thấp"

    @property
    def risk_color(self) -> str:
        mapping = {
            "Nghiêm trọng": "#ff2d55",
            "Cao":          "#ff6b35",
            "Trung bình":   "#ffd700",
            "Thấp":         "#00ff88",
        }
        return mapping.get(self.risk_level, "#00ff88")

    def vuln_count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in self.vulnerabilities:
            key = v.severity.lower()
            if key in counts:
                counts[key] += 1
        return counts


@dataclass
class ScanResult:
    """Kết quả hoàn chỉnh của một phiên quét."""
    scan_id: str
    target_url: str
    status: str = "pending"          # pending / running / completed / error
    phase: str = ""                  # Giai đoạn hiện tại
    progress: int = 0                # 0-100

    recon_data: Optional[ReconData] = None
    vuln_data: Optional[VulnData] = None
    report_html: str = ""            # Báo cáo HTML từ Gemini
    report_markdown: str = ""        # Báo cáo Markdown từ Gemini

    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển sang dict để trả về JSON."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": self.status,
            "phase": self.phase,
            "progress": self.progress,
            "error_message": self.error_message,
            "recon_data": self._recon_to_dict(),
            "vuln_data": self._vuln_to_dict(),
            "report_html": self.report_html,
            "risk_level": self.vuln_data.risk_level if self.vuln_data else "Chưa đánh giá",
            "risk_color": self.vuln_data.risk_color if self.vuln_data else "#888",
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }

    def _recon_to_dict(self) -> Dict[str, Any]:
        if not self.recon_data:
            return {}
        return {
            "target_url":  self.recon_data.target_url,
            "hostname":    self.recon_data.hostname,
            "ip_addresses": self.recon_data.ip_addresses,
            "open_ports":  self.recon_data.open_ports,
            "subdomains":  self.recon_data.subdomains,
            "dns_records": self.recon_data.dns_records,
            "server_info": self.recon_data.server_info,
        }

    def _vuln_to_dict(self) -> Dict[str, Any]:
        if not self.vuln_data:
            return {}
        return {
            "vulnerabilities": [
                {
                    "name": v.name,
                    "severity": v.severity,
                    "description": v.description,
                    "evidence": v.evidence,
                    "recommendation": v.recommendation,
                }
                for v in self.vuln_data.vulnerabilities
            ],
            "security_headers": self.vuln_data.security_headers,
            "risk_level": self.vuln_data.risk_level,
            "risk_color": self.vuln_data.risk_color,
            "vuln_counts": self.vuln_data.vuln_count_by_severity(),
        }
