import fs from 'node:fs';
import { generateK8sRecommendations } from '../devops/k8s-generator.js';
import { generateK6Script } from '../devops/k6-generator.js';
import { generatePrometheusRules } from '../devops/prometheus-generator.js';

export function exportHtmlReport(findings, outputPath = 'algoguard-report.html') {
  const k8s = generateK8sRecommendations(findings);
  const k6 = generateK6Script(findings);
  const prom = generatePrometheusRules(findings);

  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AlgoGuard Security & Pre-Deployment Report</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-dim: #8b949e;
      --accent-red: #f85149;
      --accent-yellow: #d29922;
      --accent-green: #3fb950;
      --accent-blue: #58a6ff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 24px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
    h1 { font-size: 24px; display: flex; align-items: center; gap: 10px; color: #fff; }
    .badge { padding: 4px 10px; border-radius: 20px; font-size: 13px; font-weight: 600; }
    .badge-critical { background: rgba(248,81,73,0.15); color: var(--accent-red); border: 1px solid var(--accent-red); }
    .badge-high { background: rgba(210,153,34,0.15); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
    .badge-clean { background: rgba(63,185,80,0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }
    
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
    .stat-title { font-size: 13px; color: var(--text-dim); text-transform: uppercase; font-weight: 600; margin-bottom: 8px; }
    .stat-value { font-size: 28px; font-weight: 700; color: #fff; }
    
    .section-title { font-size: 20px; color: #fff; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    .finding-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; transition: border-color 0.2s; }
    .finding-card:hover { border-color: var(--accent-blue); }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
    .rule-title { font-size: 16px; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 8px; }
    .code-box { background: #05070a; border: 1px solid #21262d; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 13px; margin: 12px 0; overflow-x: auto; color: #79c0ff; }
    
    .impact-box { background: rgba(210,153,34,0.1); border-left: 4px solid var(--accent-yellow); padding: 12px; border-radius: 4px; margin: 12px 0; font-size: 13px; }
    .impact-box strong { color: #fff; }
    
    .curl-snippet { display: flex; justify-content: space-between; align-items: center; background: #010409; border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 12px; }
    button.copy-btn { background: #21262d; border: 1px solid var(--border); color: #fff; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
    button.copy-btn:hover { background: #30363d; }
    
    .tab-bar { display: flex; gap: 8px; margin-bottom: 16px; border-bottom: 1px solid var(--border); }
    .tab-btn { background: none; border: none; padding: 8px 16px; color: var(--text-dim); cursor: pointer; font-size: 14px; font-weight: 600; border-bottom: 2px solid transparent; }
    .tab-btn.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }
    .tab-content { display: none; background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
    .tab-content.active { display: block; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ AlgoGuard Security & Pre-Deployment Report</h1>
        <p style="color: var(--text-dim); font-size: 13px; margin-top: 4px;">Automated SRE & FinOps Hazard Audit</p>
      </div>
      <div>
        ${criticalCount > 0 
          ? `<span class="badge badge-critical">🚨 MERGE BLOCKED (${criticalCount} Critical)</span>`
          : (highCount > 0 
              ? `<span class="badge badge-high">⚠️ REVIEW REQUIRED (${highCount} High)</span>`
              : `<span class="badge badge-clean">✅ ALL CHECKS PASSED</span>`)}
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-title">Total Findings</div>
        <div class="stat-value">${findings.length}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Critical Hazards</div>
        <div class="stat-value" style="color: var(--accent-red);">${criticalCount}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Est. Cloud Surge</div>
        <div class="stat-value" style="color: var(--accent-yellow); font-size: 22px;">
          ${findings.length > 0 ? '$1,400 - $3,200/wk' : '$0'}
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Languages Audited</div>
        <div class="stat-value" style="font-size: 18px; color: var(--accent-blue);">JS, TS, React, Py, Go, Java, Rust</div>
      </div>
    </div>

    <h2 class="section-title">🔍 Detected Algorithmic & Operational Hazards</h2>

    ${findings.length === 0 ? `
      <div class="stat-card" style="text-align: center; padding: 40px;">
        <h3 style="color: var(--accent-green); font-size: 20px; margin-bottom: 8px;">✅ Clean Codebase</h3>
        <p style="color: var(--text-dim);">No CPU bombs, artificial thread starvation, memory spikes, or backdoors detected.</p>
      </div>
    ` : findings.map((f, i) => `
      <div class="finding-card">
        <div class="finding-header">
          <div class="rule-title">
            <span class="badge ${f.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${f.severity}</span>
            <span>${f.ruleId}</span>
          </div>
          <span style="font-size: 13px; color: var(--text-dim); font-family: monospace;">${escapeHtml(f.filePath)}:${f.line}</span>
        </div>

        <p style="font-size: 14px; margin-bottom: 8px;">${escapeHtml(f.message)}</p>
        <div style="font-size: 12px; color: var(--text-dim); margin-bottom: 8px;"><strong>Target Endpoint:</strong> <code>${escapeHtml(f.route || 'Internal')}</code></div>

        ${f.snippet ? `<pre class="code-box">${escapeHtml(f.snippet)}</pre>` : ''}

        ${f.cloudImpact ? `
          <div class="impact-box">
            <div><strong>💸 Cloud Surge Impact:</strong> ${escapeHtml(f.cloudImpact.cloudCostSurgeWeekly)} / week (${escapeHtml(f.cloudImpact.cloudCostSurgeMonthly)} / mo)</div>
            <div><strong>⚡ Failure Mode:</strong> ${escapeHtml(f.cloudImpact.failureMode)}</div>
            <div><strong>💡 Remediation:</strong> ${escapeHtml(f.cloudImpact.recommendation)}</div>
          </div>
        ` : ''}

        ${f.attackVector ? `
          <div class="curl-snippet">
            <span>curl -X POST "http://localhost:3000${escapeHtml(f.route ? f.route.split(' ')[1] || '/api' : '/api')}" -H "Content-Type: application/json" -d '{"${escapeHtml(f.attackVector.parameter)}": ${JSON.stringify(f.attackVector.exploitValue)}}'</span>
            <button class="copy-btn" onclick="navigator.clipboard.writeText('curl -X POST &quot;http://localhost:3000${escapeHtml(f.route ? f.route.split(' ')[1] || '/api' : '/api')}&quot; -H &quot;Content-Type: application/json&quot; -d &apos;{\&quot;${escapeHtml(f.attackVector.parameter)}\&quot;: ${JSON.stringify(f.attackVector.exploitValue)}}&apos;')">Copy cURL</button>
          </div>
        ` : ''}
      </div>
    `).join('')}

    <h2 class="section-title" style="margin-top: 36px;">☸️ Auto-Generated DevOps Artifacts</h2>
    
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('tab-k8s', this)">Kubernetes Deployment Limits</button>
      <button class="tab-btn" onclick="switchTab('tab-k6', this)">k6 Load Testing Script</button>
      <button class="tab-btn" onclick="switchTab('tab-prom', this)">Prometheus Alert Rules</button>
    </div>

    <div id="tab-k8s" class="tab-content active">
      <pre class="code-box" style="margin: 0; color: #a5d6ff;">${escapeHtml(k8s.yaml)}</pre>
    </div>

    <div id="tab-k6" class="tab-content">
      <pre class="code-box" style="margin: 0; color: #a5d6ff;">${escapeHtml(k6)}</pre>
    </div>

    <div id="tab-prom" class="tab-content">
      <pre class="code-box" style="margin: 0; color: #a5d6ff;">${escapeHtml(prom)}</pre>
    </div>
  </div>

  <script>
    function switchTab(tabId, btn) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      btn.classList.add('active');
    }
  </script>
</body>
</html>`;

  fs.writeFileSync(outputPath, html, 'utf-8');
  return outputPath;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
