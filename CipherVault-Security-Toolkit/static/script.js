/* ==========================================================================
   Cyber Encryption Center — script.js
   ========================================================================== */

/* ---------------------------------------------------------------------- */
/* State                                                                  */
/* ---------------------------------------------------------------------- */
const STORAGE_KEYS = {
  history: "cec_history",
  downloads: "cec_downloads",
  passwords: "cec_passwords",
  stats: "cec_stats",
};

const ALGO_INFO = {
  caesar: {
    title: "Caesar Cipher",
    desc: "A substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.",
  },
  rot13: {
    title: "ROT13",
    desc: "A special case of the Caesar cipher with a fixed shift of 13 letters — applying it twice returns the original text.",
  },
  base64: {
    title: "Base64",
    desc: "An encoding scheme that converts data into ASCII text. It is not encryption, but is useful for safely transmitting binary-like data.",
  },
  xor: {
    title: "XOR Cipher",
    desc: "A symmetric cipher that combines each character of the message with a character from a repeating secret key using XOR.",
  },
};

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch (e) {
    return fallback;
  }
}
function saveJSON(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function getStats() {
  return loadJSON(STORAGE_KEYS.stats, { encryptions: 24, files: 8 });
}
function setStats(stats) {
  saveJSON(STORAGE_KEYS.stats, stats);
  document.getElementById("stat-encryptions").textContent = stats.encryptions;
  document.getElementById("stat-files").textContent = stats.files;
  const re = document.getElementById("report-encryptions");
  const rf = document.getElementById("report-files");
  if (re) re.textContent = stats.encryptions;
  if (rf) rf.textContent = stats.files;
}

/* ---------------------------------------------------------------------- */
/* Page navigation                                                        */
/* ---------------------------------------------------------------------- */
function showPage(pageId) {
  document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));

  const page = document.getElementById("page-" + pageId);
  if (page) page.classList.add("active");

  const nav = document.querySelector('.nav-item[data-page="' + pageId + '"]');
  if (nav) nav.classList.add("active");

  document.querySelector(".main").scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
}

/* ---------------------------------------------------------------------- */
/* Toast                                                                  */
/* ---------------------------------------------------------------------- */
let toastTimer = null;
function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
}

/* ---------------------------------------------------------------------- */
/* Cipher implementations (client-side, for text)                         */
/* ---------------------------------------------------------------------- */
function caesarShift(text, shift) {
  shift = ((shift % 26) + 26) % 26;
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function rot13(text) {
  return caesarShift(text, 13);
}

function base64Encode(text) {
  return btoa(unescape(encodeURIComponent(text)));
}
function base64Decode(text) {
  return decodeURIComponent(escape(atob(text)));
}

function xorCipher(text, key) {
  if (!key) key = "key";
  let out = "";
  for (let i = 0; i < text.length; i++) {
    out += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return out;
}
function xorToReadable(text, key) {
  // XOR output can contain control chars; show as hex so it copies/displays cleanly
  const raw = xorCipher(text, key);
  return Array.from(raw).map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
}
function xorFromReadable(hexText, key) {
  const bytes = hexText.trim().split(/\s+/).filter(Boolean).map((h) => String.fromCharCode(parseInt(h, 16)));
  return xorCipher(bytes.join(""), key);
}

function runCipher(algorithm, text, key, mode) {
  // mode: 'encrypt' | 'decrypt'
  switch (algorithm) {
    case "caesar": {
      const shift = parseInt(key, 10);
      const s = isNaN(shift) ? 3 : shift;
      return caesarShift(text, mode === "encrypt" ? s : -s);
    }
    case "rot13":
      return rot13(text); // symmetric
    case "base64":
      return mode === "encrypt" ? base64Encode(text) : base64Decode(text);
    case "xor":
      return mode === "encrypt" ? xorToReadable(text, key) : xorFromReadable(text, key);
    default:
      return text;
  }
}

/* ---------------------------------------------------------------------- */
/* Text encryption / decryption (used by Dashboard + Text Encryption page)*/
/* ---------------------------------------------------------------------- */
function encryptText(prefix) {
  const algorithm = document.getElementById(prefix + "-algorithm").value;
  const key = document.getElementById(prefix + "-key") ? document.getElementById(prefix + "-key").value : "3";
  const input = document.getElementById(prefix + "-input").value;

  if (!input.trim()) {
    showToast("Enter some text first");
    return;
  }

  try {
    const result = runCipher(algorithm, input, key, "encrypt");
    document.getElementById(prefix + "-encrypted").value = result;
    showToast("Text encrypted");

    const stats = getStats();
    stats.encryptions += 1;
    setStats(stats);

    addHistory("Text Encrypted (" + ALGO_INFO[algorithm].title + ")", result.slice(0, 60));
  } catch (e) {
    showToast("Could not encrypt that input");
  }
}

function decryptText(prefix) {
  const algorithm = document.getElementById(prefix + "-algorithm").value;
  const key = document.getElementById(prefix + "-key") ? document.getElementById(prefix + "-key").value : "3";
  const source = document.getElementById(prefix + "-encrypted").value || document.getElementById(prefix + "-input").value;

  if (!source.trim()) {
    showToast("Nothing to decrypt yet");
    return;
  }

  try {
    const result = runCipher(algorithm, source, key, "decrypt");
    const target = document.getElementById(prefix + "-decrypted");
    if (target.tagName === "INPUT") target.value = result;
    else target.value = result;
    showToast("Text decrypted");

    addHistory("Text Decrypted", result.slice(0, 60));
  } catch (e) {
    showToast("Could not decrypt — check the key/algorithm");
  }
}

function quickSelectAlgo(algo) {
  const select = document.getElementById("dash-algorithm");
  select.value = algo;
  updateAlgoInfo(algo);
  updateDashboardStatus();
  document.getElementById("dash-algorithm")
.addEventListener("change", updateDashboardStatus);
  showToast(ALGO_INFO[algo].title + " selected");
}

function updateAlgoInfo(algo) {
  const info = ALGO_INFO[algo] || ALGO_INFO.caesar;
  document.getElementById("algo-info-title").textContent = info.title;
  document.getElementById("algo-info-desc").textContent = info.desc;
}

/* ---------------------------------------------------------------------- */
/* Hash generator                                                         */
/* ---------------------------------------------------------------------- */
async function generateHash() {
  const algorithm = document.getElementById("hash-algorithm").value;
  const input = document.getElementById("hash-input").value;
  if (!input.trim()) {
    showToast("Enter text to hash");
    return;
  }
  try {
    const enc = new TextEncoder().encode(input);
    const buf = await crypto.subtle.digest(algorithm, enc);
    const hex = Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
    document.getElementById("hash-output").value = hex;
    showToast(algorithm + " hash generated");
    addHistory("Hash Generated (" + algorithm.replace("-", "") + ")", hex.slice(0, 8) + "..." + hex.slice(-4));
  } catch (e) {
    showToast("Hashing failed in this browser");
  }
}

/* ---------------------------------------------------------------------- */
/* Key generator                                                          */
/* ---------------------------------------------------------------------- */
function generateKey() {
  const length = parseInt(document.getElementById("key-length").value, 10) || 16;
  const charset = document.getElementById("key-charset").value;

  const sets = {
    all: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+",
    alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    letters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    numbers: "0123456789",
    hex: "0123456789abcdef",
  };
  const pool = sets[charset] || sets.all;
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);

  let key = "";
  for (let i = 0; i < length; i++) {
    key += pool[randomValues[i] % pool.length];
  }

  document.getElementById("key-output").value = key;
  showToast("New key generated");
  addHistory("Key Generated", "Length " + length);
}

/* ---------------------------------------------------------------------- */
/* Copy / download helpers                                                */
/* ---------------------------------------------------------------------- */
function copyText(elementId) {
  const el = document.getElementById(elementId);
  const value = el.value;
  if (!value) {
    showToast("Nothing to copy");
    return;
  }
  navigator.clipboard.writeText(value).then(
    () => showToast("Copied to clipboard"),
    () => {
      el.select();
      document.execCommand("copy");
      showToast("Copied to clipboard");
    }
  );
}

function downloadOutput(elementId, filename) {
  const el = document.getElementById(elementId);
  const value = el.value;
  if (!value) {
    showToast("Nothing to download");
    return;
  }
  const blob = new Blob([value], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast("Download started");
  addDownload(filename, "Text");
}

/* ---------------------------------------------------------------------- */
/* File encryption / decryption (talks to Flask backend)                  */
/* ---------------------------------------------------------------------- */
let selectedFile = null;

function handleFileSelect(files) {
  if (!files || !files.length) return;
  selectedFile = files[0];
  document.getElementById("file-name").textContent = selectedFile.name;
}

async function postFile(endpoint) {
  if (!selectedFile) {
    showToast("Choose a file first");
    return;
  }
  const algorithm = document.getElementById("file-algorithm").value;
  const key = document.getElementById("file-key").value;
  const statusEl = document.getElementById("file-status");

  const formData = new FormData();
  formData.append("file", selectedFile);
  formData.append("algorithm", algorithm);
  formData.append("key", key);

  statusEl.textContent = "Processing " + selectedFile.name + " …";

  try {
    const res = await fetch(endpoint, { method: "POST", body: formData });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Request failed");
    }
    const blob = await res.blob();
    const disposition = res.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="?([^"]+)"?/);
    const downloadName = match ? match[1] : "output.bin";

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = downloadName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    statusEl.textContent = "Done — " + downloadName + " downloaded.";
    showToast("File processed");
    addDownload(downloadName, "File");

    const stats = getStats();
    stats.files += 1;
    setStats(stats);
    return downloadName;
  } catch (e) {
    statusEl.textContent = "Error: " + e.message;
    showToast("File operation failed");
  }
}

async function encryptFile() {
  const name = await postFile("/api/encrypt-file");
  if (name) addHistory("File Encrypted", selectedFile ? selectedFile.name : name);
}
async function decryptFile() {
  const name = await postFile("/api/decrypt-file");
  if (name) addHistory("File Decrypted", selectedFile ? selectedFile.name : name);
}

function setupDropzone() {
  const zone = document.getElementById("dropzone");
  if (!zone) return;
  const input = document.getElementById("file-input");

  zone.addEventListener("click", () => input.click());
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("dragover");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("dragover");
    handleFileSelect(e.dataTransfer.files);
  });
}

/* ---------------------------------------------------------------------- */
/* Password manager (stored locally in this browser only)                 */
/* ---------------------------------------------------------------------- */
function pmGeneratePassword() {
  const sets = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  const randomValues = new Uint32Array(14);
  crypto.getRandomValues(randomValues);
  let pass = "";
  for (let i = 0; i < 14; i++) pass += sets[randomValues[i] % sets.length];
  document.getElementById("pm-pass").value = pass;
}

function pmAddEntry() {
  const site = document.getElementById("pm-site").value.trim();
  const user = document.getElementById("pm-user").value.trim();
  const pass = document.getElementById("pm-pass").value.trim();
  if (!site || !pass) {
    showToast("Site and password are required");
    return;
  }
  const entries = loadJSON(STORAGE_KEYS.passwords, []);
  entries.unshift({ site, user, pass, id: Date.now() });
  saveJSON(STORAGE_KEYS.passwords, entries);
  document.getElementById("pm-site").value = "";
  document.getElementById("pm-user").value = "";
  document.getElementById("pm-pass").value = "";
  renderPasswordTable();
  showToast("Entry saved");
}

function pmDeleteEntry(id) {
  let entries = loadJSON(STORAGE_KEYS.passwords, []);
  entries = entries.filter((e) => e.id !== id);
  saveJSON(STORAGE_KEYS.passwords, entries);
  renderPasswordTable();
}

function renderPasswordTable() {
  const entries = loadJSON(STORAGE_KEYS.passwords, []);
  const body = document.getElementById("pm-table-body");
  const empty = document.getElementById("pm-empty");
  if (!body) return;
  body.innerHTML = "";
  empty.style.display = entries.length ? "none" : "block";
  entries.forEach((e) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + escapeHTML(e.site) + "</td>" +
      "<td>" + escapeHTML(e.user || "—") + "</td>" +
      '<td class="mono">••••••••</td>' +
      '<td><button class="mini-btn" onclick="pmReveal(' + e.id + ', this)">Show</button> ' +
      '<button class="mini-btn" onclick="pmDeleteEntry(' + e.id + ')">Delete</button></td>';
    body.appendChild(tr);
  });
}

function pmReveal(id, btn) {
  const entries = loadJSON(STORAGE_KEYS.passwords, []);
  const entry = entries.find((e) => e.id === id);
  if (!entry) return;
  const td = btn.closest("tr").children[2];
  if (td.textContent.includes("•")) {
    td.textContent = entry.pass;
    btn.textContent = "Hide";
  } else {
    td.textContent = "••••••••";
    btn.textContent = "Show";
  }
}

/* ---------------------------------------------------------------------- */
/* History                                                                 */
/* ---------------------------------------------------------------------- */
const ACTIVITY_ICONS = {
  "Text Encrypted": { icon: "🔒", cls: "qa-cyan" },
  "Text Decrypted": { icon: "🔓", cls: "qa-green" },
  "File Encrypted": { icon: "📄", cls: "qa-blue" },
  "File Decrypted": { icon: "📄", cls: "qa-blue" },
  "Hash Generated": { icon: "#", cls: "qa-purple" },
  "Key Generated": { icon: "🔑", cls: "qa-orange" },
};

function iconFor(action) {
  for (const key of Object.keys(ACTIVITY_ICONS)) {
    if (action.indexOf(key) === 0) return ACTIVITY_ICONS[key];
  }
  return { icon: "•", cls: "qa-cyan" };
}

function addHistory(action, detail) {
  const history = loadJSON(STORAGE_KEYS.history, []);
  history.unshift({
    action,
    detail: detail || "",
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  });
  saveJSON(STORAGE_KEYS.history, history.slice(0, 200));
  renderActivity();
  renderHistoryTable();
}

function clearHistory() {
  saveJSON(STORAGE_KEYS.history, []);
  renderActivity();
  renderHistoryTable();
  showToast("History cleared");
}

function renderActivity() {
  const list = document.getElementById("activity-list");
  if (!list) return;
  const history = loadJSON(STORAGE_KEYS.history, []);
  list.innerHTML = "";

  if (!history.length) {
    list.innerHTML = '<p class="hint">No activity yet — start encrypting!</p>';
    return;
  }

  history.slice(0, 4).forEach((item) => {
    const meta = iconFor(item.action);
    const row = document.createElement("div");
    row.className = "activity-item";
    row.innerHTML =
      '<span class="activity-icon ' + meta.cls + '">' + meta.icon + "</span>" +
      '<div class="activity-body">' +
      '<div class="activity-title"><span>' + escapeHTML(item.action) + '</span><span class="activity-time">' + item.time + "</span></div>" +
      '<div class="activity-detail">' + escapeHTML(item.detail) + "</div>" +
      "</div>";
    list.appendChild(row);
  });
}

function renderHistoryTable() {
  const body = document.getElementById("history-table-body");
  if (!body) return;
  const history = loadJSON(STORAGE_KEYS.history, []);
  const empty = document.getElementById("history-empty");
  body.innerHTML = "";
  empty.style.display = history.length ? "none" : "block";
  history.forEach((item) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + escapeHTML(item.action) + "</td>" +
      "<td>" + escapeHTML(item.detail) + "</td>" +
      "<td>" + item.time + "</td>";
    body.appendChild(tr);
  });
}

/* ---------------------------------------------------------------------- */
/* Downloads                                                               */
/* ---------------------------------------------------------------------- */
function addDownload(filename, type) {
  const downloads = loadJSON(STORAGE_KEYS.downloads, []);
  downloads.unshift({
    filename,
    type,
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  });
  saveJSON(STORAGE_KEYS.downloads, downloads.slice(0, 100));
  renderDownloadsTable();
}

function renderDownloadsTable() {
  const body = document.getElementById("downloads-table-body");
  if (!body) return;
  const downloads = loadJSON(STORAGE_KEYS.downloads, []);
  const empty = document.getElementById("downloads-empty");
  body.innerHTML = "";
  empty.style.display = downloads.length ? "none" : "block";
  downloads.forEach((d) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + escapeHTML(d.filename) + "</td>" +
      "<td>" + escapeHTML(d.type) + "</td>" +
      "<td>" + d.time + "</td>";
    body.appendChild(tr);
  });
}

/* ---------------------------------------------------------------------- */
/* Security report (PDF via Flask + reportlab)                            */
/* ---------------------------------------------------------------------- */
async function generateSecurityReport() {
  const stats = getStats();
  const history = loadJSON(STORAGE_KEYS.history, []);
  const statusEl = document.getElementById("report-status");
  statusEl.textContent = "Generating report…";

  try {
    const res = await fetch("/api/security-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        stats: {
          encryptions: stats.encryptions,
          files: stats.files,
          threatLevel: "LOW",
          connection: "Active",
          strength: 87,
        },
        activity: history,
      }),
    });
    if (!res.ok) throw new Error("Server error");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "security_report.pdf";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    statusEl.textContent = "Report downloaded.";
    showToast("Security report generated");
    addDownload("security_report.pdf", "Report");
    addHistory("Security Report Generated", "PDF export");
  } catch (e) {
    statusEl.textContent = "Could not generate report. Is the Flask server running?";
    showToast("Report generation failed");
  }
}

/* ---------------------------------------------------------------------- */
/* Settings                                                                */
/* ---------------------------------------------------------------------- */
function applyAccent(color) {
  const palette = {
    cyan: { accent: "#22d3ee", strong: "#06b6d4" },
    green: { accent: "#34d399", strong: "#10b981" },
    purple: { accent: "#c084fc", strong: "#a855f7" },
    orange: { accent: "#fbbf24", strong: "#f59e0b" },
  };
  const p = palette[color] || palette.cyan;
  document.documentElement.style.setProperty("--accent", p.accent);
  document.documentElement.style.setProperty("--accent-strong", p.strong);
  localStorage.setItem("cec_accent", color);
  showToast("Accent updated");
}

function clearAllData() {
  if (!confirm("Clear all locally saved history, downloads, and passwords?")) return;
  Object.values(STORAGE_KEYS).forEach((k) => localStorage.removeItem(k));
  renderActivity();
  renderHistoryTable();
  renderDownloadsTable();
  renderPasswordTable();
  showToast("Local data cleared");
}

/* ---------------------------------------------------------------------- */
/* Utilities                                                               */
/* ---------------------------------------------------------------------- */
function escapeHTML(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

/* ---------------------------------------------------------------------- */
/* Init                                                                    */
/* ---------------------------------------------------------------------- */
function seedDemoHistoryIfEmpty() {
  const history = loadJSON(STORAGE_KEYS.history, []);
  if (history.length) return;
  const demo = [
    { action: "Text Decrypted", detail: "Hello, this is a secret message!", time: "10:18 AM" },
    { action: "Hash Generated (SHA256)", detail: "a3f6...b7c9", time: "10:20 AM" },
    { action: "File Encrypted", detail: "secret_notes.txt", time: "10:25 AM" },
    { action: "Text Encrypted (Caesar Cipher)", detail: "Khoor, wklv lv d vhfuhw phvvdjh!", time: "10:30 AM" },
  ].reverse();
  saveJSON(STORAGE_KEYS.history, demo);
}

document.addEventListener("DOMContentLoaded", () => {
  seedDemoHistoryIfEmpty();

  const stats = getStats();
  setStats(stats);

  updateStrengthMeter();
  updateDashboardStatus();

  renderActivity();
  renderHistoryTable();
  renderDownloadsTable();
  renderPasswordTable();
  setupDropzone();

  const savedAccent = localStorage.getItem("cec_accent");
  if (savedAccent) {
    document.getElementById("settings-accent").value = savedAccent;
    applyAccent(savedAccent);
  }

  // Pre-fill the dashboard demo text/output so it visually matches on first load
  const dashInput = document.getElementById("dash-input");
  const dashEncrypted = document.getElementById("dash-encrypted");
  const dashDecrypted = document.getElementById("dash-decrypted");
  if (dashInput && !dashInput.value) {
    dashInput.placeholder = "Hello, this is a secret message!";
  }
  if (dashEncrypted) dashEncrypted.placeholder = "Khoor, wklv lv d vhfuhw phvvdjh!";
  if (dashDecrypted) dashDecrypted.placeholder = "Hello, this is a secret message!";
});

function updateStrengthMeter() {

    const algo = document.getElementById("dash-algorithm").value;
    const key = document.getElementById("dash-key").value;

    let keyStrength = 50;
    let algoStrength = 50;
    let entropy = 50;

    switch(algo){

        case "caesar":
            algoStrength = 45;
            break;

        case "rot13":
            algoStrength = 35;
            break;

        case "base64":
            algoStrength = 20;
            break;

        case "xor":
            algoStrength = 85;
            break;
    }

    keyStrength = Math.min(key.length * 10,100);

    entropy = Math.min(40 + key.length * 6,100);

    const overall = Math.round(
        (keyStrength + algoStrength + entropy) / 3
    );

    document.getElementById("key-bar").style.width = keyStrength + "%";
    document.getElementById("algo-bar").style.width = algoStrength + "%";
    document.getElementById("entropy-bar").style.width = entropy + "%";
    document.getElementById("overall-bar").style.width = overall + "%";

    document.getElementById("key-value").innerText = keyStrength + "%";
    document.getElementById("algo-value").innerText = algoStrength + "%";
    document.getElementById("entropy-value").innerText = entropy + "%";
    document.getElementById("overall-value").innerText = overall + "%";

    document.getElementById("strength-pct").innerText = overall + "%";

    const circle = document.getElementById("strength-ring");

    const radius = 50;
    const circumference = 2 * Math.PI * radius;

    circle.style.strokeDasharray = circumference;

    circle.style.strokeDashoffset =
        circumference - (overall / 100) * circumference;

    const tag=document.querySelector(".ring-tag");

    if(overall>=80)
        tag.innerHTML="STRONG";
    else if(overall>=60)
        tag.innerHTML="GOOD";
    else if(overall>=40)
        tag.innerHTML="MEDIUM";
    else
        tag.innerHTML="WEAK";
}

document.getElementById("dash-algorithm")
.addEventListener("change", updateStrengthMeter);

document.getElementById("dash-key")
.addEventListener("input", updateStrengthMeter);


function updateDashboardStatus() {

    const algo = document.getElementById("dash-algorithm")?.value || "caesar";

    const connection = document.getElementById("connection-status");
    const threat = document.getElementById("threat-level");

    if(connection){
        connection.innerText = "Active";
    }

    if(!threat) return;

    switch(algo){

        case "xor":
            threat.innerText="LOW";
            threat.style.color="#22c55e";
            break;

        case "caesar":
            threat.innerText="MEDIUM";
            threat.style.color="#f59e0b";
            break;

        case "rot13":
            threat.innerText="MEDIUM";
            threat.style.color="#f59e0b";
            break;

        case "base64":
            threat.innerText="HIGH";
            threat.style.color="#ef4444";
            break;
    }

}