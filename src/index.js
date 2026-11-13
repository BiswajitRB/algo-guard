import * as core from '@actions/core';
import { scanDirectory } from './scanner.js';
import { printTerminalReport } from './reporters/terminal.js';
import { exportPostmanCollection } from './reporters/postman.js';
import { reportToGitHub } from './reporters/github-pr.js';

export async function run() {
  try {
    const scanPath = core.getInput('scan-path') || '.';
    const failOnRisk = core.getInput('fail-on-risk') !== 'false';
    const postmanExport = core.getInput('postman-export') || 'algoguard-postman-collection.json';
    const githubToken = core.getInput('github-token') || process.env.GITHUB_TOKEN;

    const findings = await scanDirectory(scanPath);

    // Terminal output
    printTerminalReport(findings);

    // Postman collection export
    if (findings.length > 0) {
      exportPostmanCollection(findings, postmanExport);
      core.setOutput('postman-path', postmanExport);
      console.log(`📦 Postman verification collection saved to: ${postmanExport}`);
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
