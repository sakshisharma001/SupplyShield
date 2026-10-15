# SupplyShield Usability Testing Guide & Viva Defense Protocol

This usability testing protocol is designed to evaluate whether a first-time viewer (such as an academic viva examiner, recruiter, or non-security developer) can understand SupplyShield within **30 seconds** without verbal coaching or external explanation.

> [!IMPORTANT]
> **Ground Rule**: Results are not pre-fabricated or invented. The test results table below is deliberately blank to be filled in live during your defense, user study, or placement viva.

---

## 1. Five-Second Comprehension Test

### Objective
Determine if a first-time user can immediately identify the core purpose and value proposition of SupplyShield within 5 seconds of seeing the empty dashboard.

### Protocol
1. Open `http://127.0.0.1:8000/dashboard` in a fresh browser session (or private browsing window).
2. Show the landing screen for exactly 5 seconds, then ask the participant to look away.
3. Ask the following two questions:
   - **Q1**: *"In your own words, what does this tool do?"*
     - *Expected understanding*: Checks Python packages for malware/hackers before you install them.
   - **Q2**: *"Who is this designed for?"*
     - *Expected understanding*: Developers, software engineers, or security teams.

---

## 2. Three-Participant Usability Task Script

### Participant Profiles
- **Participant 1 (Non-Security Developer / Junior Student)**: Familiar with `pip install`, has no prior training in AST parsing, MITRE ATT&CK, or sandbox detonation.
- **Participant 2 (Placement Evaluator / Viva Examiner)**: Senior technical assessor verifying architectural rigor, UX clarity, and safety claims.
- **Participant 3 (Security Analyst / SOC Responder)**: Assesses technical depth, MITRE technique accuracy, and report export utility.

---

### Task 1: First-Impression Comprehension (30 Seconds)
- **Prompt given to participant**: *"Look at the landing page. Without clicking anything yet, tell me what steps you would take to check a package."*
- **Success Criteria**:
  - Participant identifies the 3-step strip: (1) Paste or upload, (2) We analyse it, (3) Get a verdict & next steps.
  - Participant notices the prominent *"Try a safe package"* and *"Try a malicious package"* action buttons.
- **Time limit**: 30 seconds.

---

### Task 2: Scan Malicious Sample & Articulate Threat and Action
- **Prompt given to participant**: *"Click 'Try a malicious package', then press 'Scan code'. Tell me what happened and what you should do next."*
- **Success Criteria**:
  - Participant reads the plain-English verdict: **"Dangerous: do not install"** (Score >= 70).
  - Participant reads the human summary sentence (e.g. *"Do not install this. It attempts to steal private cloud credentials and send them over the internet."*).
  - Participant locates the **"What should I do?"** box and states the concrete remediation steps (do not install, revoke/rotate keys).
  - Participant can understand the risk without needing to know AST rule codes.
- **Time limit**: 45 seconds.

---

### Task 3: Locate Technical Findings & Export Audit Report
- **Prompt given to participant**: *"Now show me the exact line of code that triggered the warning, and export a formal audit report."*
- **Success Criteria**:
  - Participant either toggles to **Technical View** via the top bar or views the finding details.
  - Participant locates the line number and MITRE ATT&CK chip.
  - Participant clicks **"HTML Report"** or **"JSON"** or **"Copy CLI"**.
- **Time limit**: 45 seconds.

---

## 3. Empirical Test Results Log (To Be Recorded Live)

*Note: In accordance with our non-negotiable ground rules, these rows remain unpopulated until participants actually execute the test protocol.*

| Participant ID | Background / Role | Task 1: 30s Goal Met? (Y/N) | Task 2: Understood Verdict & Action? (Y/N) | Task 3: Found Line & Report? (Y/N) | Total Time (sec) | Confusion / Friction Points Observed |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Participant 1** | | | | | | |
| **Participant 2** | | | | | | |
| **Participant 3** | | | | | | |

---

## 4. Usability Design Metrics & Evaluation Criteria

| Metric | Target Goal | Implementation in SupplyShield |
| :--- | :--- | :--- |
| **Time to First Comprehension** | < 10 seconds | Plain-language headline: *"Check if a Python package is safe before you install it."* |
| **Cognitive Load for Beginners** | 0 jargon terms needed for decision | Verdicts state *"Looks safe"* / *"Dangerous: do not install"*; rule IDs stay secondary. |
| **Decision Speed on Threats** | < 15 seconds | Dedicated *"What should I do?"* action guidance card with 3 concrete bullet points. |
| **Jargon Self-Service** | 1-click tooltip or About glossary | Centralized glossary for AST, Sandbox, Canary, MITRE, SLSA, and Typosquatting. |
| **Accessibility & Contrast** | WCAG AA Compliant | Semantic contrast ratios >= 4.5:1, keyboard focus rings, `prefers-reduced-motion`. |
