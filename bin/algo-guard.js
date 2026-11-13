#!/usr/bin/env node

import { Command } from 'commander';
import { scanDirectory } from '../src/scanner.js';
import { printTerminalReport } from '../src/reporters/terminal.js';
import { exportPostmanCollection } from '../src/reporters/postman.js';

const program = new Command();

program
  .name('algo-guard')
  .description('Detect hidden CPU bombs, artificial thread sleeps, memory bombs, and backdoors in code')
  .version('1.0.0');

program
  .command('scan [targetPath]')
  .description('Scan a directory or file for algorithmic hazards')
  .option('-f, --fail-on-risk', 'Exit with code 1 if vulnerabilities are detected', false)
  .option('-o, --output-postman <file>', 'Save Postman test collection to file', 'algoguard-postman.json')
  .action(async (targetPath = '.', options) => {
    console.log(`🔍 Scanning target path: ${targetPath}...`);
    const findings = await scanDirectory(targetPath);

    printTerminalReport(findings);

    if (findings.length > 0 && options.outputPostman) {
      exportPostmanCollection(findings, options.outputPostman);
      console.log(`📦 Postman verification collection saved to: ${options.outputPostman}`);
    }

    if (options.failOnRisk && findings.length > 0) {
      process.exit(1);
    }
  });

program.parse(process.argv);

