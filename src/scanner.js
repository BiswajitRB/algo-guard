import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;

import { checkCpuBombs } from './rules/cpu-bombs.js';
import { checkSleepBombs } from './rules/sleep-bombs.js';
import { checkMemoryBombs } from './rules/memory-bombs.js';
import { checkAuthBypass } from './rules/auth-bypass.js';
import { checkReactHazards } from './rules/react-rules.js';
import { scanPolyglotFile } from './polyglot/universal-scanner.js';
import { ProjectCallGraph } from './analysis/cross-file-graph.js';
import { estimateCloudImpact } from './analysis/cost-impact.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SUPPORTED_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', // JavaScript, TypeScript, React
  '.py',                                        // Python (FastAPI, Flask, Django)
  '.go',                                        // Go (Gin, Fiber, Chi)
  '.java',                                      // Java (Spring Boot, Jakarta)
  '.rs'                                         // Rust (Actix, Axum)
]);

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next',
  '__pycache__', 'target', '.gradle', '.turbo', '.venv', 'venv'
]);

export async function scanDirectory(targetDir, options = {}) {
  const customIgnores = options.ignorePatterns || [];
  const files = collectFiles(targetDir, customIgnores);
  const allFindings = [];

  // End-to-End Cross-File Graph Analyzer
  const callGraph = new ProjectCallGraph();

  // Phase 1: Pre-index JS/TS files for cross-file call analysis
  for (const filePath of files) {
    const ext = path.extname(filePath);
    if (['.js', '.mjs', '.ts', '.jsx', '.tsx'].includes(ext)) {
      try {
        const code = fs.readFileSync(filePath, 'utf-8');
        callGraph.indexFile(filePath, code);
        callGraph.findTaintedCalls(filePath, code);
      } catch {}
    }
  }

  // Phase 2: Scan individual files with specialized AST / Structural Parsers
  for (const filePath of files) {
    try {
      const ext = path.extname(filePath);

      if (ext === '.py') {
        // Python AST Scanner
        const pythonFindings = scanPython(filePath);
        allFindings.push(...pythonFindings);
      } else if (['.go', '.java', '.rs'].includes(ext)) {
        // Polyglot Engine: Go, Java, Rust
        const code = fs.readFileSync(filePath, 'utf-8');
        const polyFindings = scanPolyglotFile(filePath, code);
        allFindings.push(...polyFindings.map(f => ({ ...f, cloudImpact: estimateCloudImpact(f) })));
      } else {
        // JavaScript / TypeScript / React AST
        const code = fs.readFileSync(filePath, 'utf-8');
        const findings = scanCode(code, filePath);
        allFindings.push(...findings);
      }
    } catch (err) {
      // Ignore unparseable files
    }
  }

  // Phase 3: Add Cross-File End-to-End Taint Analysis Findings
  const crossFileFindings = callGraph.analyzeCrossFileHazards();
  allFindings.push(...crossFileFindings.map(f => ({ ...f, cloudImpact: estimateCloudImpact(f) })));

  return allFindings;
}

export function scanPython(filePath) {
  try {
    const pythonScript = path.join(__dirname, 'python_scanner.py');
    // Resilient fallback across Linux (python3), Windows (python), and custom envs
    const pythonCandidates = [
      process.env.PYTHON_BIN,
      process.platform === 'win32' ? 'python' : 'python3',
      process.platform === 'win32' ? 'python3' : 'python'
    ].filter(Boolean);

    let stdout = null;
    for (const bin of pythonCandidates) {
      try {
        stdout = execFileSync(bin, [pythonScript, filePath], { encoding: 'utf-8' });
        if (stdout !== null) break;
      } catch (e) {
        // Try next candidate
      }
    }

    const findings = JSON.parse(stdout || '[]');
    return findings.map(f => ({
      ...f,
      cloudImpact: estimateCloudImpact(f)
    }));
  } catch (err) {
    return [];
  }
}

export function scanCode(code, filePath = 'unknown.js') {
  const findings = [];
  const lines = code.split('\n');

  let ast;
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: [
        'typescript',
        'jsx',
        'classProperties',
        'dynamicImport',
        'asyncGenerators',
        'optionalChaining',
        'nullishCoalescingOperator'
      ]
    });
  } catch (err) {
    return [];
  }

  const context = {
    report(finding) {
      // Check for inline suppression comments (// algoguard-ignore)
      const lineIdx = finding.line - 1;
      const currentLine = lines[lineIdx] || '';
      const prevLine = lineIdx > 0 ? lines[lineIdx - 1] : '';
      if (currentLine.includes('algoguard-ignore') || prevLine.includes('algoguard-ignore')) {
        return; // Suppressed by developer
      }
      findings.push(finding);
    },
    getCodeSlice(node) {
      if (!node.loc) return '';
      const start = node.loc.start.line - 1;
      const end = node.loc.end.line;
      return lines.slice(start, Math.min(start + 4, end)).join('\n');
    }
  };

  let currentRoute = null;

  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;
      if (callee.type === 'MemberExpression' && callee.property && callee.property.name) {
        const method = callee.property.name.toUpperCase();
        if (['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
          const firstArg = path.node.arguments[0];
          if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
            currentRoute = {
              method,
              path: firstArg.type === 'StringLiteral' ? firstArg.value : '/dynamic-path'
            };
          }
        }
      }

      checkSleepBombs(path, filePath, wrapContext(context, currentRoute));
      checkMemoryBombs(path, filePath, wrapContext(context, currentRoute));
      checkReactHazards(path, filePath, wrapContext(context, currentRoute));
    },

    ForStatement(path) {
      checkCpuBombs(path, filePath, wrapContext(context, currentRoute));
    },

    WhileStatement(path) {
      checkCpuBombs(path, filePath, wrapContext(context, currentRoute));
    },

    DoWhileStatement(path) {
      checkCpuBombs(path, filePath, wrapContext(context, currentRoute));
    },

    IfStatement(path) {
      checkAuthBypass(path, filePath, wrapContext(context, currentRoute));
    },

    ConditionalExpression(path) {
      checkAuthBypass(path, filePath, wrapContext(context, currentRoute));
    }
  });

  return findings;
}

function wrapContext(baseContext, currentRoute) {
  return {
    ...baseContext,
    report(finding) {
      const findingWithRoute = {
        ...finding,
        route: finding.route || (currentRoute ? `${currentRoute.method} ${currentRoute.path}` : 'Internal Function')
      };
      findingWithRoute.cloudImpact = estimateCloudImpact(findingWithRoute);
      baseContext.report(findingWithRoute);
    }
  };
}

function collectFiles(dir, customIgnores = []) {
  let results = [];
  if (!fs.existsSync(dir)) return results;

  const stat = fs.statSync(dir);
  if (stat.isFile()) {
    return [dir];
  }

  const list = fs.readdirSync(dir);
  for (const item of list) {
    if (IGNORED_DIRS.has(item)) continue;
    if (customIgnores.some(pattern => item.includes(pattern))) continue;

    const fullPath = path.join(dir, item);
    const itemStat = fs.statSync(fullPath);
    if (itemStat.isDirectory()) {
      results = results.concat(collectFiles(fullPath, customIgnores));
    } else if (SUPPORTED_EXTENSIONS.has(path.extname(item))) {
      results.push(fullPath);
    }
  }

  return results;
}
