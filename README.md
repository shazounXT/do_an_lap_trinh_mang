<<<<<<< HEAD
# Hệ Thống Multi-Agent Kiểm Thử Bảo Mật Website

> **Môn học:** Lập trình mạng  
> **Công nghệ:** Python · Flask · Google Gemini API · Multi-Agent Architecture

---

## Giới thiệu

Hệ thống sử dụng kiến trúc **Multi-Agent** để tự động hoá quy trình pentest cơ bản cho website, bao gồm thu thập thông tin, quét lỗ hổng, và tạo báo cáo AI.

```
Coordinator Agent
├── Recon Agent         → DNS · Port Scan · Subdomain Enum
├── Vulnerability Agent → Headers · SQLi · XSS · Cookie Flags
└── Report Agent        → Gemini LLM · Markdown/HTML Report
```

---

## Cấu trúc Project

```
Project_LLM_AI_Agent/
├── app.py                      # Flask entry-point
├── requirements.txt
├── README.md
│
├── agents/                     # Các agent xử lý
│   ├── coordinator_agent.py    # Điều phối pipeline
│   ├── recon_agent.py          # Thu thập thông tin
│   ├── vulnerability_agent.py  # Phát hiện lỗ hổng
│   └── report_agent.py         # Tạo báo cáo bằng LLM
│
├── toolkit/                    # Công cụ quét (pure-Python)
│   ├── dns_tools.py            # Tra cứu DNS
│   ├── subdomain_tools.py      # Dò tên miền phụ
│   ├── port_scan_tools.py      # Quét cổng
│   └── vuln_scan_tools.py      # Kiểm tra lỗ hổng HTTP
│
├── llm/
│   └── gemini_client.py        # Gọi Google Gemini API
│
├── models/
│   └── scan_result.py          # Data classes dùng chung
│
├── utils/
│   └── logger.py               # Logging tập trung
│
├── templates/                  # Jinja2 HTML templates
│   ├── layout.html
│   ├── index.html
│   └── result.html
│
└── static/
    ├── css/style.css           # Dark cybersecurity theme
    └── js/main.js              # Tab navigation & polling
```

---

## Cài đặt & Chạy

### 1. Clone / mở project

```powershell
cd "d:\Lap_Trinh_Mang\Project_LLM_AI_Agent"
```

### 2. Tạo virtual environment (khuyến nghị)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Cài dependencies

```powershell
pip install -r requirements.txt
```

### 4. Lấy Gemini API Key

1. Truy cập [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Tạo API key mới
3. Set biến môi trường:

```powershell
$env:GEMINI_API_KEY = "your_actual_api_key_here"
```

### 5. Chạy server

```powershell
python app.py
```

Mở trình duyệt: `http://localhost:5000`

---

## Sử dụng

1. Nhập URL website vào ô tìm kiếm (ví dụ: `http://testphp.vulnweb.com`)
2. Nhấn **"Bắt đầu Quét"**
3. Theo dõi tiến trình thời gian thực
4. Xem kết quả trong các tab:
   - **Thông tin** – DNS, IP, server
   - **Cổng mở** – Kết quả port scan
   - **Subdomains** – Tên miền phụ tìm thấy
   - **Lỗ hổng** – Danh sách vulnerabilities
   - **Báo cáo AI** – Phân tích từ Gemini

---

## Các target hợp lệ để test

| Website                         | Mô tả                        |
|---------------------------------|------------------------------|
| `http://testphp.vulnweb.com`    | Acunetix demo (PHP)          |
| `http://testaspnet.vulnweb.com` | Acunetix demo (ASP.NET)      |
| `https://demo.testfire.net`     | IBM AltoroMutual demo        |
| `http://dvwa.local`             | DVWA (local)                 |
| `https://juice-shop.herokuapp.com` | OWASP Juice Shop          |

> **Lưu ý:** Chỉ quét trên hệ thống mà bạn có quyền kiểm thử. Quét trái phép là vi phạm pháp luật.

---

## Kiến trúc Multi-Agent

```
 User Request
      │
      ▼
┌─────────────────────┐
│  Coordinator Agent  │
│  (Điều phối)        │
└────────┬────────────┘
         │
   ┌─────▼──────┐
   │ Recon      │  Phase 1 (0% → 50%)
   │ Agent      │  DNS · Port · Subdomain
   └─────┬──────┘
         │ ReconData
   ┌─────▼──────┐
   │ Vuln       │  Phase 2 (50% → 90%)
   │ Agent      │  Headers · SQLi · XSS
   └─────┬──────┘
         │ VulnData
   ┌─────▼──────┐
   │ Report     │  Phase 3 (90% → 100%)
   │ Agent      │  Gemini LLM Analysis
   └─────┬──────┘
         │ HTML Report
         ▼
    ScanResult
```

---

## Biến môi trường

| Biến              | Mô tả                  | Mặc định              |
|-------------------|------------------------|-----------------------|
| `GEMINI_API_KEY`  | Google Gemini API key  | `YOUR_GEMINI_API_KEY` |
| `FLASK_DEBUG`     | Debug mode             | `True`                |

---

## Phụ thuộc

- **Flask** ≥ 3.0.0 – Web framework
- **google-generativeai** ≥ 0.5.0 – Gemini API client
- Python stdlib: `socket`, `threading`, `ipaddress`, `urllib`, `ssl`, `concurrent.futures`

---

## Giấy phép & Disclaimer

Project này chỉ dành cho **mục đích học tập và nghiên cứu**. Tác giả không chịu trách nhiệm về việc sử dụng sai mục đích.
=======
# do_an_lap_trinh_mang
>>>>>>> 0829387800055ebd35235f3b921f938767e57ada
