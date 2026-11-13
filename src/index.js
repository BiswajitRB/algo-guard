import * as core from '@actions/core';
import fs from 'node:fs';
import { scanDirectory } from './scanner.js';
import { printTerminalReport } from './reporters/terminal.js';
import { exportPostmanCollection } from './reporters/postman.js';
import { exportHtmlReport } from './reporters/html-report.js';
import { exportSarifReport } from './reporters/sarif.js';
import { sendSlackWebhook } from './reporters/webhook.js';
import { reportToGitHub } from './reporters/github-pr.js';
import { generateK8sRecommendations } from './devops/k8s-generator.js';
import { generateK6Script } from './devops/k6-generator.js';
import { generatePrometheusRules } from './devops/prometheus-generator.js';

export async function run() {
  try {
    const scanPath = core.getInput('scan-path') || '.';
    const failOnRisk = core.getInput('fail-on-risk') === 'true'; // Safe default: false
    const diffBase = core.getInput('diff-base') || '';
    const postmanExport = core.getInput('postman-export') || 'algoguard-postman-collection.json';
    const slackWebhook = core.getInput('slack-webhook') || process.env.SLACK_WEBHOOK;
    const githubToken = core.getInput('github-token') || process.env.GITHUB_TOKEN;

    const findings = await scanDirectory(scanPath, { diffBase });

    // Terminal output
    printTerminalReport(findings);

    // DevOps artifacts generation
    if (findings.length > 0) {
      exportPostmanCollection(findings, postmanExport);
      core.setOutput('postman-path', postmanExport);

      exportHtmlReport(findings, 'algoguard-report.html');
      core.setOutput('html-path', 'algoguard-report.html');

      exportSarifReport(findings, 'algoguard.sarif');
      core.setOutput('sarif-path', 'algoguard.sarif');

      if (slackWebhook) {
        await sendSlackWebhook(slackWebhook, findings);
      }

      const k8s = generateK8sRecommendations(findings);
      fs.writeFileSync('algoguard-k8s.yaml', k8s.yaml, 'utf-8');
      core.setOutput('k8s-path', 'algoguard-k8s.yaml');

      const k6Script = generateK6Script(findings);
      fs.writeFileSync('algoguard-k6-stress.js', k6Script, 'utf-8');
      core.setOutput('k6-path', 'algoguard-k6-stress.js');

      const promRules = generatePrometheusRules(findings);
      fs.writeFileSync('algoguard-prometheus.yaml', promRules, 'utf-8');
      core.setOutput('prometheus-path', 'algoguard-prometheus.yaml');

      console.log(`📦 DevOps Artifacts Generated:`);
      console.log(`   - Postman Collection:     ${postmanExport}`);
      console.log(`   - HTML Dashboard:         algoguard-report.html`);
      console.log(`   - GitHub SARIF Report:    algoguard.sarif`);
      console.log(`   - Kubernetes Manifest:    algoguard-k8s.yaml`);
      console.log(`   - k6 Load Testing Script: algoguard-k6-stress.js`);
      console.log(`   - Prometheus Alert Rules: algoguard-prometheus.yaml`);
    }

    // GitHub PR report
    await reportToGitHub(findings, githubToken);

    core.setOutput('findings-count', findings.length);

    // Enforce failure in CI if risks found
    if (failOnRisk && findings.length > 0) {
      const hasCritical = findings.some(f => f.severity === 'CRITICAL');
      if (hasCritical) {
        core.setFailed(`AlgoGuard failed: Found ${findings.length} algorithmic vulnerability risk(s).`);
        process.exitCode = 1;
      }
    }
  } catch (error) {
    core.setFailed(`AlgoGuard execution error: ${error.message}`);
  }
}

// Auto-run if executed directly as GitHub Action
if (process.env.GITHUB_ACTIONS) {
  run();
}

