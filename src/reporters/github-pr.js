import * as core from '@actions/core';
import * as github from '@actions/github';

export async function reportToGitHub(findings, token) {
  // 1. Emit GitHub Workflow error annotations on exact lines
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

  // 2. If running inside a Pull Request and token is provided, post a formatted PR comment
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
            commentBody += `- **Attack Vector:** ${f.attackVector.description}\n`;
            commentBody += `\`\`\`bash\n# Test with cURL:\ncurl -X POST "http://localhost:3000${f.route ? f.route.split(' ')[1] : '/api'}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"${f.attackVector.parameter}": ${JSON.stringify(f.attackVector.exploitValue)}}'\n\`\`\`\n`;
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

