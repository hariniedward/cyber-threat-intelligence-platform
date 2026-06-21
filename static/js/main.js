/* =============================================================================
   Cyber Threat Intelligence Platform — Main JavaScript
   Handles: API calls, Chart rendering, Toast notifications, Scan engine
   ============================================================================= */

// ── Toast Notification System ─────────────────────────────────────────────────
const Toast = {
  show(message, type = "success", duration = 4000) {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type === "error" ? "error" : type === "warning" ? "warn" : ""}`;
    const icons = { success:"✓", error:"✕", warning:"⚠", info:"ℹ" };
    toast.innerHTML = `
      <span style="color:${type==="error"?"#ff4757":type==="warning"?"#ffa502":"#00d4aa"};
                   font-weight:700;margin-right:8px;">${icons[type]||"✓"}</span>
      ${message}
    `;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.animation = "slideOut .3s ease forwards";
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }
};

// ── Terminal Logger ───────────────────────────────────────────────────────────
const Terminal = {
  el: null,
  init(id) { this.el = document.getElementById(id); return this; },
  log(msg, cls = "") {
    if (!this.el) return;
    const ts   = new Date().toLocaleTimeString("en-IN", {hour12:false});
    const line = document.createElement("span");
    line.className = `log-line ${cls}`;
    line.textContent = `[${ts}] ${msg}`;
    this.el.appendChild(line);
    this.el.appendChild(document.createElement("br"));
    this.el.scrollTop = this.el.scrollHeight;
  },
  clear() { if (this.el) this.el.innerHTML = ""; }
};

// ── Severity Chart (Dashboard) ────────────────────────────────────────────────
function initSeverityChart(data) {
  const canvas = document.getElementById("severityChart");
  if (!canvas || !window.Chart) return;

  new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: ["Critical","High","Medium","Low"],
      datasets: [{
        data: [data.critical || 0, data.high || 0, data.medium || 0, data.low || 0],
        backgroundColor: ["#ff4757","#ffa502","#ffdd57","#2ed573"],
        borderColor: "#0a1020",
        borderWidth: 3,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: "#8899aa",
            font: { family: "Rajdhani", size: 13 },
            padding: 14,
          }
        },
        tooltip: {
          backgroundColor: "#111d33",
          titleColor: "#00d4aa",
          bodyColor: "#e8eaf0",
          borderColor: "#1a3050",
          borderWidth: 1,
        }
      },
      cutout: "72%",
    }
  });
}

// ── Risk Score Timeline Chart ─────────────────────────────────────────────────
function initTimelineChart(recent) {
  const canvas = document.getElementById("timelineChart");
  if (!canvas || !window.Chart) return;

  const labels = recent.map((r, i) => `#${r[0]}`);
  const scores = recent.map(r => r[6] || 0);
  const colors = scores.map(s =>
    s >= 80 ? "#ff4757" : s >= 60 ? "#ffa502" : s >= 35 ? "#ffdd57" : "#2ed573"
  );

  new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Risk Score",
        data: scores,
        backgroundColor: colors,
        borderRadius: 4,
        borderSkipped: false,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#111d33",
          titleColor: "#00d4aa",
          bodyColor: "#e8eaf0",
          borderColor: "#1a3050",
          borderWidth: 1,
        }
      },
      scales: {
        x: {
          grid: { color: "rgba(26,48,80,.3)" },
          ticks: { color: "#445566", font: { family: "Share Tech Mono", size: 10 } }
        },
        y: {
          min: 0, max: 100,
          grid: { color: "rgba(26,48,80,.3)" },
          ticks: { color: "#445566", font: { family: "Share Tech Mono", size: 10 } }
        }
      }
    }
  });
}

// ── Scan Engine ───────────────────────────────────────────────────────────────
const ScanEngine = {
  progressBar:  null,
  progressText: null,
  terminal:     null,
  running:      false,

  init() {
    this.progressBar  = document.getElementById("progressBar");
    this.progressText = document.getElementById("progressText");
    this.terminal     = Terminal.init("scanLog");
  },

  setProgress(pct, label) {
    if (this.progressBar)  this.progressBar.style.width = pct + "%";
    if (this.progressText) this.progressText.textContent = label;
  },

  async run() {
    if (this.running) { Toast.show("Scan already in progress.", "warning"); return; }
    this.running = true;

    const btn = document.getElementById("startScanBtn");
    if (btn) { btn.disabled = true; btn.textContent = "⟳ SCANNING..."; }

    Terminal.clear();
    this.terminal.log("Initializing Cyber Threat Intelligence scan...", "info");
    this.setProgress(5, "Initializing...");
    await delay(400);

    this.terminal.log("Establishing secure Tor circuit (demo mode)...", "info");
    this.setProgress(15, "Connecting...");
    await delay(600);

    this.terminal.log("Probing dark web paste sites and leak archives...", "");
    this.setProgress(30, "Crawling sources...");
    await delay(700);

    this.terminal.log("Running pattern detection engine...", "info");
    this.setProgress(50, "Detecting threats...");
    await delay(500);

    this.terminal.log("Applying AI risk scoring algorithm...", "info");
    this.setProgress(65, "Scoring threats...");
    await delay(500);

    this.terminal.log("Classifying severity levels (Critical/High/Medium/Low)...", "");
    this.setProgress(80, "Classifying...");
    await delay(400);

    // ── Actual API call ──
    try {
      const res  = await fetch("/api/run_scan", { method:"POST", headers:{"Content-Type":"application/json"} });
      const data = await res.json();

      if (data.status === "success") {
        this.setProgress(100, "Complete");
        this.terminal.log(`Scan ${data.scan_id} completed. ${data.findings} threats detected.`, "ok");

        data.results.forEach(r => {
          const icon = r.severity === "Critical" ? "🔴" : r.severity === "High" ? "🟠" : r.severity === "Medium" ? "🟡" : "🟢";
          this.terminal.log(`${icon} [${r.severity}] ${r.source} — ${r.types.join(", ")} — Score: ${r.risk_score}`, "");
        });

        this.terminal.log("Persisting findings to database...", "ok");
        Toast.show(`Scan complete — ${data.findings} threats found.`, data.findings > 0 ? "warning" : "success");

        // Refresh stats
        setTimeout(() => updateDashboardStats(), 800);
      } else {
        throw new Error(data.message);
      }
    } catch(e) {
      this.terminal.log(`ERROR: ${e.message}`, "error");
      Toast.show("Scan failed: " + e.message, "error");
    }

    this.running = false;
    if (btn) { btn.disabled = false; btn.textContent = "⚡ START SCAN"; }
  }
};

// ── Dashboard Stats Refresh ───────────────────────────────────────────────────
async function updateDashboardStats() {
  try {
    const res  = await fetch("/api/stats");
    const data = await res.json();
    const set  = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set("statTotal",    data.total);
    set("statCritical", data.critical);
    set("statHigh",     data.high);
    set("statMedium",   data.medium);
    set("statLow",      data.low);
    set("statAvgRisk",  data.avg_risk);
  } catch {}
}

// ── Report Generation ─────────────────────────────────────────────────────────
async function generateReport(type) {
  Toast.show(`Generating ${type.toUpperCase()} report...`, "info");
  try {
    const res  = await fetch("/api/generate_report", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({type})
    });
    const data = await res.json();
    if (data.status === "success") {
      Toast.show(`Report ready! Downloading...`, "success");
      window.location.href = `/api/download/${encodeURIComponent(data.file)}`;
    } else {
      Toast.show(data.message || "Report generation failed.", "error");
    }
  } catch(e) {
    Toast.show("Error: " + e.message, "error");
  }
}

// ── Email Report ──────────────────────────────────────────────────────────────
async function sendEmailReport() {
  const emailEl = document.getElementById("emailRecipient");
  const to      = emailEl ? emailEl.value.trim() : "";
  if (!to) { Toast.show("Please enter recipient email.", "warning"); return; }

  Toast.show("Sending email report...", "info");
  try {
    const res  = await fetch("/api/send_email", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({to})
    });
    const data = await res.json();
    Toast.show(data.message, data.status === "success" ? "success" : "error");
  } catch(e) {
    Toast.show("Error: " + e.message, "error");
  }
}

// ── Clear All Data ────────────────────────────────────────────────────────────
async function clearAllData() {
  if (!confirm("⚠️ Delete ALL scan data? This cannot be undone.")) return;
  try {
    const res  = await fetch("/api/clear_data", {method:"POST"});
    const data = await res.json();
    Toast.show(data.message, "success");
    setTimeout(() => location.reload(), 1000);
  } catch(e) {
    Toast.show("Error: " + e.message, "error");
  }
}

// ── Filter Table ──────────────────────────────────────────────────────────────
function filterTable(query) {
  const rows = document.querySelectorAll(".data-table tbody tr");
  const q    = query.toLowerCase();
  rows.forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
  });
}

// ── Risk Bar Helper ───────────────────────────────────────────────────────────
function getSeverityClass(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}

// ── Utility ───────────────────────────────────────────────────────────────────
const delay = ms => new Promise(r => setTimeout(r, ms));

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Attach scan button
  const scanBtn = document.getElementById("startScanBtn");
  if (scanBtn) {
    ScanEngine.init();
    scanBtn.addEventListener("click", () => ScanEngine.run());
  }

  // Highlight active nav link
  const path = window.location.pathname;
  document.querySelectorAll(".nav-link").forEach(link => {
    if (link.getAttribute("href") === path) link.classList.add("active");
  });
});
