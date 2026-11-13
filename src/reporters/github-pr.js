import * as core from '@actions/core';
import * as github from '@actions/github';
import { generateK8sRecommendations } from '../devops/k8s-generator.js';

export async function reportToGitHub(findings, token) {
  // 1. Emit GitHub Workflow error/warning annotations on exact lines
  findings.forEach(finding => {
    const isCritical = finding.severity === 'CRITICAL';
    const annotationFunc = isCritical ? core.error : core.warning;
    
    annotationFunc(`[${finding.ruleId}] ${finding.message}`, {
      file: finding.filePath,
      startLine: finding.line,
      startColumn: finding.column,
      title: `AlgoGuard: ${finding.ruleId} (${finding.severity})`
    });
  });

  // 2. Render GitHub Actions Job Summary ($GITHUB_STEP_SUMMARY Dashboard)
  await renderJobSummary(findings);

  // 3. If running inside a Pull Request and token is provided, post a formatted PR comment
  if (!token) return;

  try {
    const context = github.context;
    if (context.payload && context.payload.pull_request) {
      const octokit = github.getOctokit(token);
      const prNumber = context.payload.pull_request.number;
      const owner = context.repo.owner;
      const repo = context.repo.repo;

      let commentBody = `## 🛡️ AlgoGuard Security Scan Report\n\n`;
      if (findings.length === 0) {
        commentBody += `✅ **Clean!** No algorithmic resource bombs, thread sleeps, or backdoor bypasses detected.\n`;
      } else {
        commentBody += `⚠️ **Found ${findings.length} potential algorithmic vulnerability/risk issue(s)** in this PR.\n\n`;
        commentBody += `| Severity | Rule | File & Line | Endpoint | Est. Cloud Bill Surge |\n`;
        commentBody += `|:---|:---|:---|:---|:---|\n`;

        findings.forEach(f => {
          const badge = f.severity === 'CRITICAL' ? '🔴 `CRITICAL`' : '🟡 `HIGH`';
          const surge = f.cloudImpact ? `💸 **${f.cloudImpact.cloudCostSurgeWeekly}**/wk` : 'N/A';
          commentBody += `| ${badge} | **${f.ruleId}** | \`${f.filePath}:${f.line}\` | \`${f.route || 'Internal'}\` | ${surge} |\n`;
        });

        commentBody += `\n### Detailed Breakdown, Exploit Vectors & Financial DoS\n`;
        findings.forEach((f, idx) => {
          commentBody += `#### ${idx + 1}. [${f.severity}] ${f.ruleId}\n`;
          commentBody += `- **Location:** \`${f.filePath}:${f.line}\`\n`;
          commentBody += `- **Explanation:** ${f.message}\n`;
          if (f.cloudImpact) {
            commentBody += `- **💸 Cloud Auto-Scaling Surge:** ${f.cloudImpact.autoscalingBehavior}\n`;
            commentBody += `- **💸 Projected Financial Impact:** \`${f.cloudImpact.cloudCostSurgeWeekly}\` / week (\`${f.cloudImpact.cloudCostSurgeMonthly}\` / month)\n`;
            commentBody += `- **⚡ Failure Mode:** ${f.cloudImpact.failureMode}\n`;
            commentBody += `- **💡 Safe Remediation:** ${f.cloudImpact.recommendation}\n`;
          }
          if (f.attackVector) {
            const routeMethod = f.route && f.route.startsWith('POST') ? 'POST' : 'GET';
            let routeUrl = '/api/endpoint';
            if (f.route && f.route.includes(' ') && !f.route.includes('Internal')) {
              routeUrl = f.route.split(' ')[1];
            } else if (typeof f.attackVector.exploitValue === 'string' && f.attackVector.exploitValue.startsWith('/')) {
              routeUrl = f.attackVector.exploitValue;
            }
            commentBody += `\`\`\`bash\n# Test with cURL:\ncurl -X ${routeMethod} "http://localhost:3000${routeUrl}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"${f.attackVector.parameter}": ${JSON.stringify(f.attackVector.exploitValue)}}'\n\`\`\`\n`;
          }
        });
      }

      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: prNumber,
        body: commentBody
      });
    }
  } catch (err) {
    core.warning(`Could not post PR comment: ${err.message}`);
  }
}

async function renderJobSummary(findings) {
  try {
    core.summary.addHeading('🛡️ AlgoGuard Pre-Deployment Risk Dashboard', 1);

    if (findings.length === 0) {
      core.summary.addRaw('✅ **All pre-deployment algorithmic checks passed cleanly!** No CPU bombs, thread starvation, or backdoors detected.');
      await core.summary.write();
      return;
    }

    const hasCritical = findings.some(f => f.severity === 'CRITICAL');
    const statusBanner = hasCritical
      ? '🚨 **STATUS: MERGE BLOCKED** (Critical algorithmic starvation or backdoor risks detected)'
      : '⚠️ **STATUS: WARNING** (High complexity or unthrottled parameters detected)';
    
    core.summary.addRaw(statusBanner + '\n\n');

    // Table of findings
    const tableHeader = [
      { data: 'Severity', header: true },
      { data: 'Rule ID', header: true },
      { data: 'Location', header: true },
      { data: 'Endpoint', header: true },
      { data: 'Est. Cloud Surge', header: true }
    ];

    const tableRows = findings.map(f => [
      f.severity === 'CRITICAL' ? '🔴 CRITICAL' : '🟡 HIGH',
      f.ruleId,
      `${f.filePath}:${f.line}`,
      f.route || 'Internal',
      f.cloudImpact ? f.cloudImpact.cloudCostSurgeWeekly : 'N/A'
    ]);

    core.summary.addTable([tableHeader, ...tableRows]);

    // Recommended Kubernetes Pod Limits
    const k8s = generateK8sRecommendations(findings);
    core.summary.addHeading('☸️ Recommended Kubernetes Resource Limits for this Release', 2);
    core.summary.addCode(k8s.yaml, 'yaml');

    core.summary.addHeading('📦 Generated DevOps Artifacts', 2);
    core.summary.addList([
      '**Kubernetes Deployment & Ingress:** `algoguard-k8s.yaml`',
      '**k6 Automated Load Testing Script:** `algoguard-k6-stress.js`',
      '**Prometheus Monitoring & Alerting Rules:** `algoguard-prometheus.yaml`',
      '**Postman Verification Collection:** `algoguard-postman.json`'
    ]);

    await core.summary.write();
  } catch (err) {
    // Fail gracefully if running outside GitHub Actions runner
  }
}
