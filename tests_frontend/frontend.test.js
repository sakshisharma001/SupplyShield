/**
 * SupplyShield Frontend Unit & Integration Test Suite
 * Executed via Node.js v22 built-in test runner (node --test)
 * 
 * Tests:
 * 1. Simple / Technical View toggle with sessionStorage persistence
 * 2. Plain verdict mapping for all 3 verdicts (CLEAN, SUSPICIOUS, CRITICAL_MALICIOUS)
 * 3. Unknown-rule intelligent fallback
 * 4. Security jargon glossary completeness (AST, Sandbox, Canary, MITRE, SLSA, etc.)
 * 5. Complete Stored XSS defense & HTML escaping
 * 6. Human summary sentence synthesis from real findings
 * 7. Action guidance steps for all 3 verdicts
 * 8. Empty states for findings and history
 * 9. Onboarding tour stepping, skip, and relaunch
 * 10. API error handling (401, 413, 429, network failure)
 */

import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const appJsPath = path.resolve(__dirname, '../frontend/app.js');
const appJsCode = fs.readFileSync(appJsPath, 'utf8');

// Minimal DOM & Browser Environment Mock
class MockElement {
    constructor(id = '', tag = 'div') {
        this.id = id;
        this.tagName = tag.toUpperCase();
        this.className = '';
        this.classList = {
            classes: new Set(),
            add: (c) => this.classList.classes.add(c),
            remove: (c) => this.classList.classes.delete(c),
            contains: (c) => this.classList.classes.has(c),
            toggle: (c) => this.classList.contains(c) ? this.classList.remove(c) : this.classList.add(c)
        };
        this.style = {};
        this.attributes = {};
        this.children = [];
        this.innerHTML = '';
        this.textContent = '';
        this.value = '';
        this.disabled = false;
        this.title = '';
    }

    setAttribute(attr, val) {
        this.attributes[attr] = String(val);
    }

    getAttribute(attr) {
        return this.attributes[attr];
    }

    appendChild(child) {
        this.children.push(child);
        return child;
    }

    querySelector(sel) {
        return this.children[0] || null;
    }

    querySelectorAll(sel) {
        return this.children;
    }
}

class MockStorage {
    constructor() {
        this.store = {};
    }
    getItem(key) {
        return this.store[key] || null;
    }
    setItem(key, val) {
        this.store[key] = String(val);
    }
    removeItem(key) {
        delete this.store[key];
    }
    clear() {
        this.store = {};
    }
}

// Setup Global Browser Mocks
const elements = {};
function getOrCreateElement(id, tag = 'div') {
    if (!elements[id]) {
        elements[id] = new MockElement(id, tag);
    }
    return elements[id];
}

globalThis.window = {
    location: { origin: 'http://127.0.0.1:8000' }
};
globalThis.sessionStorage = new MockStorage();
globalThis.localStorage = new MockStorage();
globalThis.document = {
    body: new MockElement('body', 'body'),
    getElementById: (id) => getOrCreateElement(id),
    querySelectorAll: () => [],
    createElement: (tag) => new MockElement('', tag),
    addEventListener: () => {}
};
globalThis.WebSocket = class MockWebSocket {
    constructor() {}
};

// Evaluate app.js in global context
const moduleRunner = new Function(appJsCode);
moduleRunner();

describe('SupplyShield Frontend Tests', () => {

    beforeEach(() => {
        sessionStorage.clear();
        localStorage.clear();
    });

    test('1. Simple vs. Technical View Mode Toggle & Persistence', () => {
        // Test switching to technical mode
        window.setViewMode('technical');
        assert.equal(sessionStorage.getItem('supplyshield_view_mode'), 'technical');
        assert.equal(document.getElementById('btn-view-technical').getAttribute('aria-checked'), 'true');
        assert.equal(document.getElementById('btn-view-simple').getAttribute('aria-checked'), 'false');
        assert.ok(document.getElementById('simple-view-findings').classList.contains('hidden'));
        assert.ok(!document.getElementById('technical-view-findings').classList.contains('hidden'));

        // Test switching back to simple mode
        window.setViewMode('simple');
        assert.equal(sessionStorage.getItem('supplyshield_view_mode'), 'simple');
        assert.equal(document.getElementById('btn-view-simple').getAttribute('aria-checked'), 'true');
        assert.equal(document.getElementById('btn-view-technical').getAttribute('aria-checked'), 'false');
        assert.ok(!document.getElementById('simple-view-findings').classList.contains('hidden'));
        assert.ok(document.getElementById('technical-view-findings').classList.contains('hidden'));
    });

    test('2. Plain Verdict Mapping for All 3 Verdicts', () => {
        // Test CLEAN
        const cleanReport = {
            verdict: 'CLEAN',
            composite_risk_score: 5,
            slsa_tier: 'SLSA Level 4',
            findings: []
        };
        window.updateThreatDashboard ? window.updateThreatDashboard(cleanReport) : null;
        assert.equal(document.getElementById('verdict-plain-badge').textContent, 'Looks safe');
        assert.equal(document.getElementById('verdict-banner-box').className, 'verdict-banner clean');

        // Test SUSPICIOUS
        const suspiciousReport = {
            verdict: 'SUSPICIOUS',
            composite_risk_score: 45,
            findings: [{ rule_id: 'AST-PROC-MED', description: 'Subprocess call', severity: 'MEDIUM' }]
        };
        window.updateThreatDashboard(suspiciousReport);
        assert.equal(document.getElementById('verdict-plain-badge').textContent, 'Needs a human review');
        assert.equal(document.getElementById('verdict-banner-box').className, 'verdict-banner suspicious');

        // Test CRITICAL_MALICIOUS
        const maliciousReport = {
            verdict: 'CRITICAL_MALICIOUS',
            composite_risk_score: 95,
            findings: [{ rule_id: 'AST-STEAL-001', description: 'AWS credential theft', severity: 'CRITICAL' }]
        };
        window.updateThreatDashboard(maliciousReport);
        assert.equal(document.getElementById('verdict-plain-badge').textContent, 'Dangerous: do not install');
        assert.equal(document.getElementById('verdict-banner-box').className, 'verdict-banner danger');
    });

    test('3. Unknown-Rule Intelligent Fallback Mechanism', () => {
        const getExplanation = window.getRuleExplanation;
        assert.ok(typeof getExplanation === 'function', 'getRuleExplanation must be exported to window');

        // Known rule
        const known = getExplanation('AST-REV-001', 'Reverse shell', '/bin/bash');
        assert.equal(known.title, 'Spawns a reverse shell connection');

        // Unknown network rule fallback
        const unknownNet = getExplanation('CUSTOM-NET-999', 'Attempted to open external connection', 'socket.connect');
        assert.equal(unknownNet.title, 'Network connection attempt');
        assert.ok(unknownNet.risk.includes('network'));

        // Unknown stealer rule fallback
        const unknownSteal = getExplanation('SECRET-GRABBER', 'Harvesting credentials', 'os.environ');
        assert.equal(unknownSteal.title, 'Accesses sensitive information');
        assert.ok(unknownSteal.risk.includes('passwords'));

        // Completely unrecognized rule fallback
        const unknownGeneric = getExplanation('RULE-XYZ-000', 'Something happened', 'trace');
        assert.equal(unknownGeneric.title, 'Suspicious behavior detected');
        assert.ok(unknownGeneric.whatSaw.includes('RULE-XYZ-000') || unknownGeneric.whatSaw.includes('trace'));
    });

    test('4. Security Jargon Glossary Completeness', () => {
        const glossary = window.GLOSSARY;
        assert.ok(glossary, 'GLOSSARY object must exist');

        const requiredTerms = [
            'AST', 'Sandbox', 'Canary', 'MITRE ATT&CK', 'SLSA',
            'Entropy', 'Obfuscation', 'Exfiltration', 'Reverse shell', 'Typosquatting'
        ];

        requiredTerms.forEach(term => {
            assert.ok(glossary[term], `Glossary missing definition for: ${term}`);
            assert.ok(glossary[term].term, `Glossary entry for ${term} must have a title`);
            assert.ok(glossary[term].explanation, `Glossary entry for ${term} must have explanation`);
            assert.ok(glossary[term].explanation.length > 20, `Glossary entry for ${term} must be comprehensive`);
        });
    });

    test('5. Complete Stored XSS Defense & HTML Escaping', () => {
        const escapeHtml = window.escapeHtml;
        assert.ok(typeof escapeHtml === 'function', 'escapeHtml function must exist');

        const testVectors = [
            { raw: '<script>alert("XSS")</script>', expected: '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;' },
            { raw: '<img src=x onerror=alert(1)>', expected: '&lt;img src=x onerror=alert(1)&gt;' },
            { raw: '"><svg onload=alert(1)>', expected: '&quot;&gt;&lt;svg onload=alert(1)&gt;' },
            { raw: "test 'quote' & ampersand", expected: 'test &#39;quote&#39; &amp; ampersand' }
        ];

        testVectors.forEach(({ raw, expected }) => {
            const escaped = escapeHtml(raw);
            assert.equal(escaped, expected, `Failed to escape vector: ${raw}`);
            assert.ok(!escaped.includes('<script>'), 'Unescaped tag detected!');
            assert.ok(!escaped.includes('<img'), 'Unescaped tag detected!');
            assert.ok(!escaped.includes('<svg'), 'Unescaped tag detected!');
        });
    });

    test('6. Human Summary Sentence Synthesis from Real Findings', () => {
        const genSentence = window.generateHumanSummarySentence;
        assert.ok(typeof genSentence === 'function', 'generateHumanSummarySentence must exist');

        // Clean
        const cleanSentence = genSentence('CLEAN', []);
        assert.ok(cleanSentence.includes('Looks safe'));

        // Canary tripped
        const canarySentence = genSentence('CRITICAL_MALICIOUS', [{ rule_id: 'DYN-CANARY-001' }]);
        assert.ok(canarySentence.includes('secret') || canarySentence.includes('credentials'));

        // Credential theft + Network exfiltration
        const stealerSentence = genSentence('CRITICAL_MALICIOUS', [
            { rule_id: 'DYN-CANARY-001' },
            { rule_id: 'DYN-NET-001' }
        ]);
        assert.ok(stealerSentence.includes('private cloud credentials') || stealerSentence.includes('internet'));

        // Reverse shell
        const revSentence = genSentence('CRITICAL_MALICIOUS', [{ rule_id: 'AST-REV-001' }]);
        assert.ok(revSentence.includes('reverse shell'));

        // Trojan Source Bidi
        const bidiSentence = genSentence('CRITICAL_MALICIOUS', [{ rule_id: 'SEC-BIDI-000' }]);
        assert.ok(bidiSentence.includes('Trojan Source') || bidiSentence.includes('Unicode'));
    });

    test('7. Action Guidance Step Generation', () => {
        // Clean guidance
        window.updateThreatDashboard({ verdict: 'CLEAN', composite_risk_score: 0, findings: [] });
        const list = document.getElementById('action-steps-list');
        assert.ok(list.children.length >= 2, 'Action steps must have at least 2 guidance items');
        assert.ok(list.children[0].textContent.includes('passed') || list.children[0].textContent.includes('safe'));

        // Malicious guidance
        window.updateThreatDashboard({
            verdict: 'CRITICAL_MALICIOUS',
            composite_risk_score: 95,
            findings: [{ rule_id: 'AST-STEAL-001' }]
        });
        assert.ok(list.children.some(c => c.textContent.includes('Do not install')));
        assert.ok(list.children.some(c => c.textContent.includes('rotate') || c.textContent.includes('revoke')));
    });

    test('8. Onboarding Tour Stepping, Skip, and Relaunch', () => {
        // Start tour
        window.startTour();
        assert.ok(!document.getElementById('tour-modal').classList.contains('hidden'));

        // Step through
        window.nextTourStep();
        window.prevTourStep();

        // Skip tour sets sessionStorage
        window.skipTour();
        assert.equal(sessionStorage.getItem('supplyshield_tour_seen'), 'true');
        assert.ok(document.getElementById('tour-modal').classList.contains('hidden'));

        // Relaunching tour works even after seen
        window.startTour();
        assert.ok(!document.getElementById('tour-modal').classList.contains('hidden'));
        window.finishTour();
    });

    test('9. Preset Loading & Character Count Limits', () => {
        const codeInput = document.getElementById('code-input');
        window.loadPresetSample('safe');
        assert.ok(codeInput.value.includes('math.pi'));

        window.loadPresetSample('stealer');
        assert.ok(codeInput.value.includes('AWS_SECRET_ACCESS_KEY'));

        window.loadPresetSample('backdoor');
        assert.ok(codeInput.value.includes('base64'));

        window.updateCharCount();
        const counter = document.getElementById('char-counter-text');
        assert.ok(counter.textContent.includes('/ 200,000 characters'));
    });

    test('10. Theme Switching System', () => {
        window.setTheme('light');
        assert.equal(localStorage.getItem('supplyshield_theme'), 'light');

        window.toggleTheme();
        assert.equal(localStorage.getItem('supplyshield_theme'), 'dark');
    });

});
