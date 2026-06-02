import express from "express";
import rateLimit from "express-rate-limit";
import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { URL } from "node:url";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "50kb" }));
app.use(express.static("public"));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Terlalu banyak request. Coba lagi nanti." }
});

app.use("/api/", limiter);

const PRIVATE_RANGES = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^192\.168\./,
  /^0\./,
  /^::1$/,
  /^fc/i,
  /^fd/i,
  /^fe80/i
];

function isPrivateIp(ip) {
  if (!ip) return true;
  if (net.isIP(ip) === 4) return PRIVATE_RANGES.some((r) => r.test(ip));
  if (net.isIP(ip) === 6) return PRIVATE_RANGES.some((r) => r.test(ip));
  return true;
}

function normalizeUrl(raw) {
  if (!raw || typeof raw !== "string") throw new Error("URL wajib diisi.");
  let input = raw.trim();
  if (!/^https?:\/\//i.test(input)) input = "https://" + input;
  const u = new URL(input);
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Hanya URL http/https yang diperbolehkan.");
  u.hash = "";
  return u;
}

async function validatePublicTarget(urlObj) {
  const hostname = urlObj.hostname;
  if (hostname === "localhost" || hostname.endsWith(".local")) {
    throw new Error("Target localhost/internal tidak diperbolehkan.");
  }

  const records = await dns.lookup(hostname, { all: true });
  if (!records.length) throw new Error("DNS target tidak ditemukan.");

  for (const rec of records) {
    if (isPrivateIp(rec.address)) {
      throw new Error("Target mengarah ke IP private/internal. Scan diblokir demi keamanan.");
    }
  }

  return records.map((r) => r.address);
}

async function fetchWithTimeout(url, options = {}, ms = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, {
      ...options,
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent": "PassiveSecurityHeaderScanner/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ...(options.headers || {})
      }
    });
  } finally {
    clearTimeout(timer);
  }
}

async function getTlsInfo(urlObj) {
  if (urlObj.protocol !== "https:") {
    return {
      enabled: false,
      grade: "high",
      title: "Website tidak menggunakan HTTPS",
      detail: "URL masih menggunakan HTTP. Data berisiko disadap atau dimodifikasi di jaringan."
    };
  }

  return await new Promise((resolve) => {
    const socket = tls.connect({
      host: urlObj.hostname,
      port: Number(urlObj.port || 443),
      servername: urlObj.hostname,
      timeout: 8000
    }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      socket.end();

      let daysLeft = null;
      if (cert?.valid_to) {
        daysLeft = Math.ceil((new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24));
      }

      const findings = [];
      if (daysLeft !== null && daysLeft < 0) {
        findings.push({
          severity: "critical",
          title: "Sertifikat SSL/TLS sudah kedaluwarsa",
          detail: `Sertifikat kedaluwarsa pada ${cert.valid_to}.`
        });
      } else if (daysLeft !== null && daysLeft <= 14) {
        findings.push({
          severity: "medium",
          title: "Sertifikat SSL/TLS hampir kedaluwarsa",
          detail: `Sertifikat akan kedaluwarsa sekitar ${daysLeft} hari lagi.`
        });
      }

      resolve({
        enabled: true,
        protocol,
        cipher: cipher?.name || null,
        validFrom: cert?.valid_from || null,
        validTo: cert?.valid_to || null,
        daysLeft,
        findings
      });
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        enabled: true,
        findings: [{
          severity: "medium",
          title: "Tidak dapat membaca informasi TLS",
          detail: "Koneksi TLS timeout saat mengambil informasi sertifikat."
        }]
      });
    });

    socket.on("error", (err) => {
      resolve({
        enabled: true,
        findings: [{
          severity: "high",
          title: "Masalah koneksi TLS",
          detail: err.message
        }]
      });
    });
  });
}

function h(headers, key) {
  return headers.get(key);
}

function addFinding(findings, severity, title, detail, recommendation) {
  findings.push({ severity, title, detail, recommendation });
}

function analyzeHeaders(headers, urlObj) {
  const findings = [];
  const passed = [];

  const strictTransport = h(headers, "strict-transport-security");
  if (urlObj.protocol === "https:") {
    if (!strictTransport) {
      addFinding(
        findings,
        "high",
        "Header HSTS belum aktif",
        "Strict-Transport-Security tidak ditemukan.",
        "Tambahkan Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
      );
    } else {
      passed.push("HSTS aktif");
    }
  }

  const csp = h(headers, "content-security-policy");
  if (!csp) {
    addFinding(
      findings,
      "high",
      "Content Security Policy belum ada",
      "Header CSP tidak ditemukan. Risiko XSS lebih tinggi jika ada celah input/script.",
      "Gunakan CSP ketat, contoh awal: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    );
  } else {
    passed.push("CSP tersedia");
    if (csp.includes("'unsafe-inline'") || csp.includes("*")) {
      addFinding(
        findings,
        "medium",
        "CSP masih longgar",
        "CSP ditemukan, tetapi masih mengandung wildcard atau unsafe-inline.",
        "Kurangi wildcard dan hindari unsafe-inline jika memungkinkan."
      );
    }
  }

  const xfo = h(headers, "x-frame-options");
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !frameAncestors) {
    addFinding(
      findings,
      "medium",
      "Proteksi clickjacking belum terlihat",
      "Tidak ada X-Frame-Options atau CSP frame-ancestors.",
      "Gunakan X-Frame-Options: DENY/SAMEORIGIN atau CSP frame-ancestors 'none'/'self'."
    );
  } else {
    passed.push("Proteksi framing tersedia");
  }

  const nosniff = h(headers, "x-content-type-options");
  if (!nosniff || !/nosniff/i.test(nosniff)) {
    addFinding(
      findings,
      "medium",
      "X-Content-Type-Options belum nosniff",
      "Browser dapat mencoba menebak MIME type file.",
      "Tambahkan X-Content-Type-Options: nosniff"
    );
  } else {
    passed.push("MIME sniffing protection aktif");
  }

  const referrer = h(headers, "referrer-policy");
  if (!referrer) {
    addFinding(
      findings,
      "low",
      "Referrer-Policy belum ada",
      "URL asal dapat ikut terkirim ke website lain.",
      "Gunakan Referrer-Policy: strict-origin-when-cross-origin atau no-referrer."
    );
  } else {
    passed.push("Referrer-Policy tersedia");
  }

  const permissions = h(headers, "permissions-policy");
  if (!permissions) {
    addFinding(
      findings,
      "low",
      "Permissions-Policy belum ada",
      "Fitur browser seperti kamera, mikrofon, geolocation belum dibatasi via header.",
      "Tambahkan Permissions-Policy sesuai kebutuhan aplikasi."
    );
  } else {
    passed.push("Permissions-Policy tersedia");
  }

  const cors = h(headers, "access-control-allow-origin");
  if (cors === "*") {
    addFinding(
      findings,
      "medium",
      "CORS terlalu terbuka",
      "Access-Control-Allow-Origin bernilai wildcard (*).",
      "Batasi origin hanya ke domain yang benar-benar membutuhkan akses."
    );
  }

  const server = h(headers, "server");
  const powered = h(headers, "x-powered-by");
  if (server || powered) {
    addFinding(
      findings,
      "low",
      "Informasi teknologi server terekspos",
      `Header yang terlihat: ${server ? "Server=" + server : ""} ${powered ? "X-Powered-By=" + powered : ""}`,
      "Sembunyikan atau minimalkan header versi/teknologi server."
    );
  }

  return { findings, passed };
}

function analyzeCookies(headers) {
  const findings = [];
  const passed = [];
  const rawSetCookie = headers.getSetCookie ? headers.getSetCookie() : [];
  const cookies = rawSetCookie.length ? rawSetCookie : [];

  if (!cookies.length) {
    passed.push("Tidak ada Set-Cookie pada response awal");
    return { findings, passed, cookies: [] };
  }

  for (const cookie of cookies) {
    const name = cookie.split("=")[0];
    const lower = cookie.toLowerCase();

    if (!lower.includes("httponly")) {
      addFinding(findings, "medium", `Cookie ${name} tanpa HttpOnly`, "Cookie dapat lebih mudah diakses script browser jika terjadi XSS.", "Tambahkan atribut HttpOnly.");
    }
    if (!lower.includes("secure")) {
      addFinding(findings, "medium", `Cookie ${name} tanpa Secure`, "Cookie dapat terkirim melalui koneksi non-HTTPS.", "Tambahkan atribut Secure.");
    }
    if (!lower.includes("samesite")) {
      addFinding(findings, "low", `Cookie ${name} tanpa SameSite`, "Cookie lebih rentan pada skenario CSRF tertentu.", "Tambahkan SameSite=Lax atau Strict sesuai kebutuhan.");
    }
  }

  if (!findings.length) passed.push("Cookie flags terlihat aman pada response awal");
  return { findings, passed, cookies: cookies.map((c) => c.split(";")[0]) };
}

function scoreFromFindings(findings) {
  let score = 100;
  for (const f of findings) {
    if (f.severity === "critical") score -= 30;
    if (f.severity === "high") score -= 20;
    if (f.severity === "medium") score -= 10;
    if (f.severity === "low") score -= 4;
  }
  score = Math.max(0, score);

  let grade = "A";
  if (score < 90) grade = "B";
  if (score < 75) grade = "C";
  if (score < 60) grade = "D";
  if (score < 40) grade = "E";

  return { score, grade };
}

async function checkWellKnown(urlObj) {
  const findings = [];
  const passed = [];

  const checks = [
    { path: "/security.txt", label: "security.txt root" },
    { path: "/.well-known/security.txt", label: "security.txt well-known" },
    { path: "/robots.txt", label: "robots.txt" }
  ];

  for (const c of checks) {
    const testUrl = new URL(c.path, urlObj.origin);
    try {
      const res = await fetchWithTimeout(testUrl.toString(), { method: "GET" }, 5000);
      if (res.status >= 200 && res.status < 300) {
        passed.push(`${c.label} tersedia`);
      }
    } catch {
      // silent passive check
    }
  }

  if (!passed.some((x) => x.includes("security.txt"))) {
    addFinding(
      findings,
      "info",
      "security.txt tidak ditemukan",
      "File security.txt membantu researcher melaporkan celah keamanan secara bertanggung jawab.",
      "Tambahkan /.well-known/security.txt berisi kontak security resmi."
    );
  }

  return { findings, passed };
}

app.post("/api/scan", async (req, res) => {
  const startedAt = Date.now();

  try {
    const urlObj = normalizeUrl(req.body?.url);
    const resolvedIps = await validatePublicTarget(urlObj);

    const tlsInfo = await getTlsInfo(urlObj);

    let response = await fetchWithTimeout(urlObj.toString(), { method: "GET" }, 12000);
    const redirectLocation = response.headers.get("location");

    const allFindings = [];
    const passed = [];

    if (urlObj.protocol === "http:") {
      addFinding(
        allFindings,
        "high",
        "URL menggunakan HTTP",
        "Traffic tidak terenkripsi.",
        "Aktifkan HTTPS dan redirect semua HTTP ke HTTPS."
      );
    }

    if ([301, 302, 303, 307, 308].includes(response.status) && redirectLocation) {
      passed.push(`Redirect terdeteksi ke ${redirectLocation}`);
    }

    if (tlsInfo.findings) allFindings.push(...tlsInfo.findings);

    const headerAnalysis = analyzeHeaders(response.headers, urlObj);
    allFindings.push(...headerAnalysis.findings);
    passed.push(...headerAnalysis.passed);

    const cookieAnalysis = analyzeCookies(response.headers);
    allFindings.push(...cookieAnalysis.findings);
    passed.push(...cookieAnalysis.passed);

    const wellKnown = await checkWellKnown(urlObj);
    allFindings.push(...wellKnown.findings);
    passed.push(...wellKnown.passed);

    const { score, grade } = scoreFromFindings(allFindings.filter((f) => f.severity !== "info"));

    res.json({
      ok: true,
      target: urlObj.toString(),
      host: urlObj.hostname,
      resolvedIps,
      status: response.status,
      finalUrl: response.url,
      responseTimeMs: Date.now() - startedAt,
      tls: tlsInfo,
      headers: Object.fromEntries(response.headers.entries()),
      cookies: cookieAnalysis.cookies,
      score,
      grade,
      findings: allFindings,
      passed,
      disclaimer: "Gunakan hanya untuk website milik sendiri atau yang Anda punya izin tertulis untuk diuji."
    });
  } catch (err) {
    res.status(400).json({
      ok: false,
      error: err?.message || "Scan gagal."
    });
  }
});

app.listen(PORT, () => {
  console.log(`URL Vulnerability Scanner running at http://localhost:${PORT}`);
});
