import fs from 'node:fs';
import path from 'node:path';
import { installGitHook } from '../devops/hook-installer.js';

export function runInitWizard(options = {}) {
  console.log('\n🚀 Initializing AlgoGuard in repository...\n');

  // 1. Create algoguard.config.json
  const configPath = 'algoguard.config.json';
  const config = {
    scanPath: options.scanPath || '.',
    failOnRisk: false,
    diffBase: 'origin/main',
    ignore: ['node_modules', 'dist', 'coverage', 'tests', '__tests__', 'spec'],
    reporters: ['terminal', 'postman', 'k8s', 'k6', 'prometheus']
  };

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
  console.log(`✅ Created configuration file: ${configPath}`);

  // 2. Create .github/workflows/algo-guard.yml
  const workflowsDir = path.join('.github', 'workflows');
  if (!fs.existsSync(workflowsDir)) {
    fs.mkdirSync(workflowsDir, { recursive: true });
  }

  const workflowPath = path.join(workflowsDir, 'algo-guard.yml');
  const workflowYaml = `name: "AlgoGuard: SRE & FinOps Pre-Deployment Shield"

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main]

jobs:
  audit:
    name: Algorithmic Hazard & FinOps Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # Required for PR comments
      security-events: write # Required if uploading SARIF to GitHub Security tab

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full fetch needed for git diff monorepo scan

      - name: Run AlgoGuard Scanner
        uses: your-org/algo-guard@v1
        with:
          scan-path: "."
          diff-base: "origin/main"
          fail-on-risk: "false" # Non-blocking warning mode
          github-token: \${{ secrets.GITHUB_TOKEN }}

      - name: Upload DevOps Artifacts (K8s, k6, Postman)
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: algoguard-devops-bundle
          path: |
            algoguard-k8s.yaml
            algoguard-k6-stress.js
            algoguard-prometheus.yaml
            algoguard-postman.json
            algoguard-report.html
`;

  fs.writeFileSync(workflowPath, workflowYaml, 'utf-8');
  console.log(`✅ Created GitHub Actions workflow: ${workflowPath}`);

  // 3. Install local Git pre-push hook
  try {
    const hookPath = installGitHook('.');
    console.log(`✅ Installed local Git pre-push hook: ${hookPath}`);
  } catch (err) {
    console.log(`ℹ️ Git hook skipped: ${err.message}`);
  }

  console.log('\n🎉 AlgoGuard initialization complete!');
  console.log('👉 Next: Run "npx algo-guard scan" or commit .github/workflows/algo-guard.yml to enable in PRs.\n');
}

