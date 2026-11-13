# 🛡️ AlgoGuard

> **The SRE & FinOps Pre-Deployment Shield: Automated Runtime Hazard Detection, Kubernetes Resource Sizing, and k6 Stress Generation for Pull Requests.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-green.svg)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-%3E%3D3.8-yellow.svg)](https://python.org/)
[![Java](https://img.shields.io/badge/Java-Spring%20Boot-orange.svg)](https://spring.io/)
[![Go](https://img.shields.io/badge/Go-Gin%20%7C%20Fiber-00ADD8.svg)](https://go.dev/)
[![Rust](https://img.shields.io/badge/Rust-Actix%20%7C%20Axum-black.svg)](https://www.rust-lang.org/)
[![React](https://img.shields.io/badge/React-JSX%20%7C%20TSX-61dafb.svg)](https://react.dev/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Ready-orange.svg)](https://github.com/features/actions)

---

## 🎯 The Problem

Developers (or malicious insiders) can introduce catastrophic resource exhaustion or backdoors into codebases. Standard linters and security scanners look for known CVEs or hardcoded passwords, but miss **algorithmic hazards** and **hidden backdoors**:

- **CPU Pegging / DoS:** A loop bound multiplied by an untrusted request parameter (`for (let i = 0; i < factor * 500000; i++)`) disguised as a "tax calculation" or "search sync".
- **Artificial Thread Starvation:** A stealth `await sleep(8000)` or blocking sync delay inside an HTTP route handler that starves the worker pool during peak traffic.
- **Memory Bombs:** Allocating huge memory buffers (`Buffer.alloc(chunk_size * 1024 * 1024)`) causing immediate OOM (Out-of-Memory) crashes.
- **Short-Circuit Backdoors:** A condition comparing arbitrary parameters against secret keys (`if (auth_ticket === 'x_super_override_99')`) that immediately returns admin tokens without querying the authentication database.

Rogue developers **do not name endpoints `/test` or `/bomb`**. They give them innocent names (`/api/v2/finance/calculate-tax`, `/api/v1/profile/sync-state`). 

**AlgoGuard analyzes the Abstract Syntax Tree (AST) and behavioral execution flow, catching these issues regardless of what the functions, variables, or routes are named.**

---

## 🚀 Quick Start as a GitHub Action

DevOps teams can protect their repositories in under 30 seconds by adding this workflow:

### `.github/workflows/algo-guard.yml`
```yaml
name: "AlgoGuard: Algorithmic Security Gate"

on:
  pull_request:
    branches: [main, master, develop]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # Required for posting PR review comments
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run AlgoGuard Scanner
        uses: your-org/algo-guard@v1
        with:
          scan-path: "./src"
          fail-on-risk: "true" # Fails CI if CRITICAL/HIGH risks are found
          postman-export: "algoguard-postman.json"
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload Postman Proof Collection
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: algoguard-postman-proof
          path: algoguard-postman.json
```

---

## 💻 CLI Usage (Local / Pre-Push)

Install or run directly via `npx`:

```bash
# 🚀 1. Setup Wizard: Initialize config, GitHub workflow, and git hooks in 1 command
npx algo-guard init

# 🛡️ 2. Install local Git pre-push hook (blocks dangerous pushes locally)
npx algo-guard install-hook

# 🔍 3. Standard Scan (generates Postman, K8s limits, k6 tests & Prometheus alerts)
npx algo-guard scan ./src

# 📊 4. Generate Interactive Standalone HTML Dashboard Report
npx algo-guard scan ./src --html

# 🛡️ 5. Export OASIS SARIF v2.1.0 for GitHub Security / Code Scanning tab
npx algo-guard scan ./src --sarif algoguard.sarif

# 💬 6. Dispatch Instant Alerts to Slack / Discord Webhook
npx algo-guard scan ./src --slack-webhook https://hooks.slack.com/services/...

# ⚡ 7. High-speed Monorepo Mode: Only scan files changed in PR
npx algo-guard scan ./src --diff main
```

---

## 📊 Sample Terminal Output

```text
🛡️  AlgoGuard Security & Algorithmic Bomb Scanner
────────────────────────────────────────────────────────────
⚠️  Found 4 algorithmic vulnerability/risk issue(s):

[1]  CRITICAL  AUTH_SHORT_CIRCUIT_BACKDOOR
   Location: controllers/auth.js:9:2
   Route:    POST /api/v1/auth/verify-token
   Message:  Potential backdoor: Condition on 'auth_ticket' grants authentication or elevated privilege bypassing regular flow.
   Code:
      |   if (auth_ticket === 'x_super_override_99') {
      |     return res.json({ authenticated: true, role: 'admin' });
   Exploit Vector: Returns elevated credentials/role ('token') directly inside branch
   Test Parameter: auth_ticket = "x_super_override_99"
   cURL Proof:
      curl -X POST "http://localhost:3000/api/v1/auth/verify-token" \
        -H "Content-Type: application/json" \
        -d '{"auth_ticket": "x_super_override_99"}'
────────────────────────────────────────────────────────────
[2]  CRITICAL  UNBOUNDED_CPU_LOOP
   Location: controllers/finance.js:11:2
   Route:    POST /api/v2/finance/calculate-tax
   Message:  Loop condition multiplies request input with an extreme factor. High risk of 100% CPU lockup / DoS.
   Code:
      |   for (let i = 0; i < factor * 500000; i++) {
      |     computed += Math.sin(i) * Math.cos(i);
      |   }
   Exploit Vector: Sending a high numeric value will force the server into an astronomical number of iterations.
   Test Parameter: factor = 1000
   cURL Proof:
      curl -X POST "http://localhost:3000/api/v2/finance/calculate-tax" \
        -H "Content-Type: application/json" \
        -d '{"factor": 1000}'
────────────────────────────────────────────────────────────
📦 Postman verification collection saved to: algoguard-postman.json
```

---

## 🧩 Supported Detection Rules

| Rule ID | Severity | What It Catches |
| :--- | :---: | :--- |
| `UNBOUNDED_CPU_LOOP` | **CRITICAL** | Loops where bounds are multiplied by user request input or extreme iteration limits. |
| `REGEX_CATASTROPHIC_BACKTRACKING` | **CRITICAL** | Catastrophic ReDoS exponential backtracking patterns `(a+)+` that freeze CPU cores. |
| `BUSY_WAIT_SPIN_LOOP` | **CRITICAL** | Spin loops (`while(Date.now() < ...)`) that monopolize CPU cores and block event loops. |
| `ARTIFICIAL_THREAD_SLEEP` | **CRITICAL** | Synchronous or async sleep/delays inside HTTP handlers that cause thread/worker pool starvation. |
| `UNBOUNDED_MEMORY_ALLOCATION` | **CRITICAL** | `Buffer.alloc()` or array sizing derived from untrusted input without bounds, causing OOM. |
| `AUTH_SHORT_CIRCUIT_BACKDOOR` | **CRITICAL** | Short-circuit branches returning tokens or admin privileges based on raw parameter matches. |
| `HIGH_LATENCY_TIMEOUT` | **HIGH** | `setTimeout` or delays exceeding 3,000ms configured in active request paths. |

---

## 🧪 Running the Tests

```bash
npm test
```

All rules are verified against real-world clean vs. malicious controller fixtures located in `test/fixtures/`.

---

## 📄 License

MIT License. Free and open source for DevOps, platform, and security engineering teams.

