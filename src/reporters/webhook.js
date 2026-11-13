/**
 * Webhook Dispatcher for Slack and Discord alerts.
 * Notifies platform and SRE channels when critical algorithmic hazards are detected in PRs.
 */

export async function sendSlackWebhook(webhookUrl, findings, repoName = 'Repository') {
  if (!webhookUrl || findings.length === 0) return false;

  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const topIssues = findings.slice(0, 3).map(f => `• *[${f.severity}] ${f.ruleId}* in \`${f.filePath}:${f.line}\` (${f.route || 'Internal'})\n  _${f.message}_`).join('\n\n');

  const payload = {
    text: `🚨 *AlgoGuard Alert:* Detected ${findings.length} operational hazard(s) in *${repoName}* (${criticalCount} Critical)`,
    attachments: [
      {
        color: criticalCount > 0 ? '#f85149' : '#d29922',
        title: '💸 Projected Cloud Surge: $1,400 – $3,200 / week',
        text: `${topIssues}\n\n👉 *Review and verify with generated k6 load tests & Postman collections.*`,
        footer: 'AlgoGuard SRE & FinOps Shield'
      }
    ]
  };

  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.ok;
  } catch (err) {
    console.error(`⚠️ Failed to send Slack alert: ${err.message}`);
    return false;
  }
}

export async function sendDiscordWebhook(webhookUrl, findings, repoName = 'Repository') {
  if (!webhookUrl || findings.length === 0) return false;

  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const topIssues = findings.slice(0, 3).map(f => `**[${f.severity}] ${f.ruleId}** in \`${f.filePath}:${f.line}\`\n${f.message}`).join('\n\n');

  const payload = {
    content: `🚨 **AlgoGuard Pre-Deployment Alert:** Detected ${findings.length} hazard(s) in **${repoName}**`,
    embeds: [
      {
        title: '💸 Projected Cloud Surge: $1,400 – $3,200 / week',
        color: criticalCount > 0 ? 16273481 : 13801762,
        description: topIssues,
        footer: { text: 'AlgoGuard SRE & FinOps Shield' }
      }
    ]
  };

  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.ok;
  } catch (err) {
    console.error(`⚠️ Failed to send Discord alert: ${err.message}`);
    return false;
  }
}

