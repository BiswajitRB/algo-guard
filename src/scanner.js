import fs from 'node:fs';
import path from 'node:path';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;

import { checkCpuBombs } from './rules/cpu-bombs.js';
import { checkSleepBombs } from './rules/sleep-bombs.js';
import { checkMemoryBombs } from './rules/memory-bombs.js';
import { checkAuthBypass } from './rules/auth-bypass.js';
import { estimateCloudImpact } from './analysis/cost-impact.js';

const SUPPORTED_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx']);
const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next']);

export async function scanDirectory(targetDir) {
  const files = collectFiles(targetDir);
  const allFindings = [];

  for (const filePath of files) {
    try {
      const code = fs.readFileSync(filePath, 'utf-8');
      const findings = scanCode(code, filePath);
      allFindings.push(...findings);
    } catch (err) {
      // Ignore unparseable non-code files or syntax issues in non-standard files
    }
  }

  return allFindings;
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
      findings.push(finding);
    },
    getCodeSlice(node) {
      if (!node.loc) return '';
      const start = node.loc.start.line - 1;
      const end = node.loc.end.line;
      return lines.slice(start, Math.min(start + 4, end)).join('\n');
    }
  };

  // Keep track of active HTTP route scope
  let currentRoute = null;

  traverse(ast, {
    // Detect Express / router HTTP methods: app.get('/...', ...), router.post('/...', ...)
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

      // Run CallExpression rules
      checkSleepBombs(path, filePath, wrapContext(context, currentRoute));
      checkMemoryBombs(path, filePath, wrapContext(context, currentRoute));
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
        route: currentRoute ? `${currentRoute.method} ${currentRoute.path}` : 'Internal Function'
      };
      findingWithRoute.cloudImpact = estimateCloudImpact(findingWithRoute);
      baseContext.report(findingWithRoute);
    }
  };
}

function collectFiles(dir) {
  let results = [];
  if (!fs.existsSync(dir)) return results;

  const stat = fs.statSync(dir);
  if (stat.isFile()) {
    return [dir];
  }

  const list = fs.readdirSync(dir);
  for (const item of list) {
    if (IGNORED_DIRS.has(item)) continue;
    const fullPath = path.join(dir, item);
    const itemStat = fs.statSync(fullPath);
    if (itemStat.isDirectory()) {
      results = results.concat(collectFiles(fullPath));
    } else if (SUPPORTED_EXTENSIONS.has(path.extname(item))) {
      results.push(fullPath);
    }
  }

  return results;
}

