import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Git Diff Extractor for High-Speed Monorepo Scanning.
 * Instead of scanning 50,000 files across a monorepo, extracts only files
 * modified or added in the active Pull Request or commit diff.
 */

export function getChangedFiles(baseBranch = null, stagedOnly = false) {
  try {
    let command = 'git diff --name-only --diff-filter=ACMRT';

    if (stagedOnly) {
      command = 'git diff --cached --name-only --diff-filter=ACMRT';
    } else if (baseBranch) {
      // In CI / PR context: git diff --name-only origin/main...HEAD
      command = `git diff --name-only --diff-filter=ACMRT ${baseBranch}...HEAD`;
    } else {
      // Default local working copy modified files
      command = 'git diff --name-only --diff-filter=ACMRT HEAD';
    }

    const stdout = execSync(command, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'ignore'] });
    const files = stdout
      .split('\n')
      .map(f => f.trim())
      .filter(Boolean)
      .map(f => path.resolve(f))
      .filter(f => fs.existsSync(f));

    return files;
  } catch (err) {
    // If git diff fails (e.g. shallow clone or not a git repo), return null to fall back to standard scan
    return null;
  }
}
