#!/usr/bin/env node

import fs from 'node:fs';
import { Command } from 'commander';
import { scanDirectory } from '../src/scanner.js';
import { printTerminalReport } from '../src/reporters/terminal.js';
import { exportPostmanCollection } from '../src/reporters/postman.js';
import { generateK8sRecommendations } from '../src/devops/k8s-generator.js';
import { generateK6Script } from '../src/devops/k6-generator.js';
import { generatePrometheusRules } from '../src/devops/prometheus-generator.js';
import { installGitHook, uninstallGitHook } from '../src/devops/hook-installer.js';

const program = new Command();

program
  .name('algo-guard')
  .description('DevOps Pre-Deployment Shield: Detects algorithmic bombs, auto-scales K8s limits, and generates k6 stress tests')
  .version('1.2.0');

program
  .command('install-hook')
  .description('Install local git pre-push hook to block algorithmic bombs before push')
  .action(() => {
    try {
      const hookPath = installGitHook('.');
      console.log(`✅ AlgoGuard pre-push git hook installed at: ${hookPath}`);
      console.log('🛡️  Your local git push commands are now protected against algorithmic hazards!');
    } catch (err) {
      console.error(`❌ Failed to install hook: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command('uninstall-hook')
  .description('Remove local git pre-push hook')
  .action(() => {
    const removed = uninstallGitHook('.');
    if (removed) {
      console.log('✔ AlgoGuard pre-push git hook uninstalled.');
    } else {
      console.log('ℹ️ No AlgoGuard pre-push hook found to uninstall.');
    }
  });

program
  .command('scan [targetPath]')
  .description('Scan code for algorithmic hazards and generate DevOps infrastructure artifacts')
  .option('-f, --fail-on-risk', 'Exit with code 1 if vulnerabilities are detected', false)
  .option('-o, --output-postman <file>', 'Save Postman test collection to file', 'algoguard-postman.json')
  .option('--ignore <patterns...>', 'Ignore directory or file patterns (e.g. --ignore tests mocks)', [])
  .option('--devops-bundle', 'Auto-generate full DevOps pack (K8s limits, k6 stress test, Prometheus alerts)', true)
  .action(async (targetPath = '.', options) => {
    console.log(`🔍 Scanning target path: ${targetPath}...`);
    const findings = await scanDirectory(targetPath, { ignorePatterns: options.ignore });

    printTerminalReport(findings);

    if (findings.length > 0) {
      if (options.outputPostman) {
        exportPostmanCollection(findings, options.outputPostman);
        console.log(`📦 Postman verification collection: ${options.outputPostman}`);
      }

      if (options.devopsBundle) {
        const k8s = generateK8sRecommendations(findings);
        fs.writeFileSync('algoguard-k8s.yaml', k8s.yaml, 'utf-8');
        console.log(`☸️  Kubernetes Limits & Ingress Config: algoguard-k8s.yaml`);

        const k6Script = generateK6Script(findings);
        fs.writeFileSync('algoguard-k6-stress.js', k6Script, 'utf-8');
        console.log(`🚀 k6 Load Testing Script:          algoguard-k6-stress.js`);

        const promRules = generatePrometheusRules(findings);
        fs.writeFileSync('algoguard-prometheus.yaml', promRules, 'utf-8');
        console.log(`📊 Prometheus Alerting Rules:        algoguard-prometheus.yaml`);
      }
    }

    if (options.failOnRisk && findings.length > 0) {
      process.exit(1);
    }
  });

program.parse(process.argv);
