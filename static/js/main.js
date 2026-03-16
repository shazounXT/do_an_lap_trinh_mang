/**
 * main.js – PentestAI Frontend Logic
 *
 * Chức năng:
 *  1. startPolling(scanId) – Poll /api/status mỗi 2s để cập nhật progress bar
 *  2. initTabs()           – Tab navigation trên trang kết quả
 *  3. Các hiệu ứng UI phụ trợ
 */

"use strict";

/* ── Constants ──────────────────────────────────────────── */
const POLL_INTERVAL_MS = 2000;   // Tần suất poll (ms)
const MAX_LOG_LINES    = 50;     // Số dòng log tối đa hiển thị

/* ── Kiểm tra DOM ready ─────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  addHoverEffects();
  animateCounters();
});


/* ══════════════════════════════════════════════════════════
   1.  Progress Polling
   ══════════════════════════════════════════════════════════ */

let _pollTimer = null;
let _prevPhase = "";
let _logLines  = 0;

/**
 * Bắt đầu polling trạng thái scan.
 * Tự động ngừng khi status = completed | error.
 *
 * @param {string} scanId - Scan ID
 */
function startPolling(scanId) {
  const progressSection = document.getElementById("progressSection");
  const resultContent   = document.getElementById("resultContent");
  const progressBar     = document.getElementById("progressBar");
  const progressPct     = document.getElementById("progressPct");
  const phaseText       = document.getElementById("phaseText");
  const scanLog         = document.getElementById("scanLog");

  if (!progressSection) return;

  // Xoá log cũ
  if (scanLog) scanLog.innerHTML = "";
  appendLog(scanLog, "Kết nối đến hệ thống scan…", "");

  _pollTimer = setInterval(async () => {
    try {
      const resp = await fetch(`/api/status/${scanId}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();

      // ── Cập nhật progress bar ──────────────────────────
      const pct = Math.min(data.progress || 0, 100);
      if (progressBar) {
        progressBar.style.width = pct + "%";
      }
      if (progressPct) progressPct.textContent = pct + "%";

      // ── Cập nhật phase text ───────────────────────────
      const phase = data.phase || "";
      if (phaseText) phaseText.textContent = phase || "Đang xử lý…";

      // ── Log thay đổi phase ─────────────────────────────
      if (phase && phase !== _prevPhase) {
        _prevPhase = phase;
        const cls = phase.includes("✓") ? "success"
                  : phase.includes("Lỗi") ? "error"
                  : "";
        appendLog(scanLog, phase, cls);
      }

      // ── Hoàn thành ────────────────────────────────────
      if (data.status === "completed") {
        clearInterval(_pollTimer);
        appendLog(scanLog, "✅ Quét hoàn tất! Đang tải kết quả…", "success");

        // Tải đầy đủ kết quả rồi re-render trang
        await loadAndRenderResult(scanId, progressSection, resultContent);
        return;
      }

      // ── Lỗi ──────────────────────────────────────────
      if (data.status === "error") {
        clearInterval(_pollTimer);
        appendLog(scanLog, `❌ Lỗi: ${data.error || "Không xác định"}`, "error");
        if (phaseText) phaseText.textContent = "Quét thất bại!";
        return;
      }

    } catch (err) {
      console.error("[Polling] Lỗi:", err);
      appendLog(scanLog, `Lỗi kết nối: ${err.message}`, "error");
    }
  }, POLL_INTERVAL_MS);
}


/**
 * Tải kết quả đầy đủ từ API và re-render trang kết quả.
 */
async function loadAndRenderResult(scanId, progressSection, resultContent) {
  try {
    const resp = await fetch(`/api/result/${scanId}`);
    if (!resp.ok) {
      // Kết quả chưa sẵn sàng, thử lại sau 1s
      setTimeout(() => loadAndRenderResult(scanId, progressSection, resultContent), 1000);
      return;
    }
    // Reload trang để Flask render kết quả đầy đủ với Jinja2 template
    window.location.reload();
  } catch (err) {
    console.error("[Result] Lỗi tải kết quả:", err);
    setTimeout(() => loadAndRenderResult(scanId, progressSection, resultContent), 2000);
  }
}


/**
 * Thêm dòng log vào panel.
 */
function appendLog(logEl, msg, cls) {
  if (!logEl) return;
  _logLines++;

  // Giới hạn số dòng
  if (_logLines > MAX_LOG_LINES) {
    const firstChild = logEl.querySelector(".log-line");
    if (firstChild) firstChild.remove();
  }

  const now = new Date();
  const time = [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map(n => String(n).padStart(2, "0"))
    .join(":");

  const line = document.createElement("p");
  line.className = "log-line";
  line.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-msg ${cls}">${escapeHtml(msg)}</span>
  `;
  logEl.appendChild(line);

  // Auto scroll xuống cuối
  logEl.scrollTop = logEl.scrollHeight;
}


/* ══════════════════════════════════════════════════════════
   2.  Tab Navigation
   ══════════════════════════════════════════════════════════ */

/**
 * Khởi tạo hệ thống tab trên trang kết quả.
 */
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  if (!tabBtns.length) return;

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const tabId = btn.dataset.tab;

      // Deactivate all
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

      // Activate selected
      btn.classList.add("active");
      const panel = document.getElementById(`tab-${tabId}`);
      if (panel) {
        panel.classList.add("active");
        // Animate vào
        panel.style.opacity = "0";
        panel.style.transform = "translateY(8px)";
        requestAnimationFrame(() => {
          panel.style.transition = "opacity .25s ease, transform .25s ease";
          panel.style.opacity = "1";
          panel.style.transform = "translateY(0)";
        });
      }
    });
  });
}


/* ══════════════════════════════════════════════════════════
   3.  Hiệu ứng UI
   ══════════════════════════════════════════════════════════ */

/**
 * Hiệu ứng glowing khi hover vào agent cards.
 */
function addHoverEffects() {
  document.querySelectorAll(".agent-card").forEach((card, i) => {
    card.style.animationDelay = `${i * .1}s`;
    card.style.animation = "fadeInUp .5s ease both";
  });
}

/**
 * Animation đếm số cho các count badges.
 */
function animateCounters() {
  document.querySelectorAll(".count-num").forEach(el => {
    const target = parseInt(el.textContent, 10);
    if (isNaN(target) || target === 0) return;

    let current = 0;
    const step = Math.ceil(target / 20);
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = current;
      if (current >= target) clearInterval(timer);
    }, 40);
  });
}


/* ══════════════════════════════════════════════════════════
   4.  Utilities
   ══════════════════════════════════════════════════════════ */

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}


/* ── Inject CSS animation ───────────────────────────────── */
const _animStyle = document.createElement("style");
_animStyle.textContent = `
  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(16px); }
    to   { opacity: 1; transform: translateY(0); }
  }
`;
document.head.appendChild(_animStyle);
