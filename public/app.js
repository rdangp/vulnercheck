const urlInput = document.querySelector("#urlInput");
const scanBtn = document.querySelector("#scanBtn");
const loading = document.querySelector("#loading");
const errorBox = document.querySelector("#errorBox");
const result = document.querySelector("#result");
const exportBtn = document.querySelector("#exportBtn");

let lastResult = null;

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function hideError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderKV(selector, rows) {
  const el = document.querySelector(selector);
  el.innerHTML = rows.map(([k, v]) => `
    <div>
      <span>${esc(k)}</span>
      <span>${esc(v)}</span>
    </div>
  `).join("");
}

function severityRank(s) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 5;
}

function renderFindings(findings) {
  const box = document.querySelector("#findings");
  const sorted = [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  if (!sorted.length) {
    box.innerHTML = `<div class="finding"><h3>Tidak ada temuan risiko utama pada pengecekan pasif ini.</h3></div>`;
    return;
  }

  box.innerHTML = sorted.map((f) => `
    <article class="finding">
      <div class="finding-top">
        <span class="sev ${esc(f.severity)}">${esc(f.severity)}</span>
        <h3>${esc(f.title)}</h3>
      </div>
      <p>${esc(f.detail)}</p>
      ${f.recommendation ? `<p class="rec"><strong>Rekomendasi:</strong> ${esc(f.recommendation)}</p>` : ""}
    </article>
  `).join("");
}

function renderPassed(passed) {
  const ul = document.querySelector("#passed");
  if (!passed?.length) {
    ul.innerHTML = `<li>Belum ada checklist yang lolos dari response awal.</li>`;
    return;
  }
  ul.innerHTML = passed.map((p) => `<li>${esc(p)}</li>`).join("");
}

function render(data) {
  lastResult = data;

  document.querySelector("#score").textContent = data.score;
  document.querySelector("#grade").textContent = `Grade ${data.grade}`;
  document.querySelector("#status").textContent = data.status;
  document.querySelector("#time").textContent = `${data.responseTimeMs} ms`;
  document.querySelector("#tls").textContent = data.tls?.enabled ? (data.tls.protocol || "HTTPS") : "No HTTPS";

  renderKV("#targetInfo", [
    ["Target", data.target],
    ["Host", data.host],
    ["Resolved IP", (data.resolvedIps || []).join(", ")],
    ["Final URL", data.finalUrl || "-"],
    ["TLS Valid To", data.tls?.validTo || "-"],
    ["TLS Days Left", data.tls?.daysLeft ?? "-"]
  ]);

  renderFindings(data.findings || []);
  renderPassed(data.passed || []);
  document.querySelector("#headers").textContent = JSON.stringify(data.headers || {}, null, 2);

  result.classList.remove("hidden");
}

async function scan() {
  const url = urlInput.value.trim();
  if (!url) {
    showError("Masukkan URL terlebih dahulu.");
    return;
  }

  hideError();
  result.classList.add("hidden");
  loading.classList.remove("hidden");
  scanBtn.disabled = true;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "Scan gagal.");

    render(data);
  } catch (err) {
    showError(err.message || "Terjadi kesalahan.");
  } finally {
    loading.classList.add("hidden");
    scanBtn.disabled = false;
  }
}

scanBtn.addEventListener("click", scan);
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") scan();
});

exportBtn.addEventListener("click", () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `scan-result-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
});
