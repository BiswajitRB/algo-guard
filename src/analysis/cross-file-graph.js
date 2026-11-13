import fs from 'node:fs';
import path from 'node:path';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;

/**
 * Cross-File Call Graph & Taint Propagation Engine.
 * Resolves the "Single-File Limitation":
 * When file A (controller) receives `req.body.factor` and passes it to `calculateTax(factor)`
 * imported from file B (service/util), this engine propagates taint into file B!
 */

export class ProjectCallGraph {
  constructor() {
    this.functionDefinitions = new Map(); // funcName -> { filePath, params: ['factor', ...], bodyNode }
    this.taintedFunctionCalls = [];       // { callerFile, targetFuncName, taintedParamIndices: [0] }
  }

  // Phase 1: Index all function declarations across the repository
  indexFile(filePath, code) {
    let ast;
    try {
      ast = parse(code, {
        sourceType: 'unambiguous',
        plugins: ['typescript', 'jsx', 'classProperties', 'dynamicImport']
      });
    } catch {
      return;
    }

    const defs = this.functionDefinitions;

    traverse(ast, {
      FunctionDeclaration(p) {
        if (p.node.id && p.node.id.name) {
          const params = p.node.params.map(param => param.name || (param.left && param.left.name) || 'param');
          defs.set(p.node.id.name, {
            filePath,
            name: p.node.id.name,
            params,
            node: p.node
          });
        }
      },
      VariableDeclarator(p) {
        if (p.node.id && p.node.id.name && p.node.init) {
          if (p.node.init.type === 'ArrowFunctionExpression' || p.node.init.type === 'FunctionExpression') {
            const params = p.node.init.params.map(param => param.name || (param.left && param.left.name) || 'param');
            defs.set(p.node.id.name, {
              filePath,
              name: p.node.id.name,
              params,
              node: p.node.init
            });
          }
        }
      }
    });
  }

  // Phase 2: Find calls in controllers that pass req.body / req.query into external functions
  findTaintedCalls(filePath, code) {
    let ast;
    try {
      ast = parse(code, {
        sourceType: 'unambiguous',
        plugins: ['typescript', 'jsx', 'classProperties', 'dynamicImport']
      });
    } catch {
      return;
    }

    const taintedCalls = this.taintedFunctionCalls;

    traverse(ast, {
      CallExpression(p) {
        const callee = p.node.callee;
        let funcName = null;
        if (callee.type === 'Identifier') {
          funcName = callee.name;
        } else if (callee.type === 'MemberExpression' && callee.property && callee.property.name) {
          funcName = callee.property.name;
        }

        if (funcName && p.node.arguments && p.node.arguments.length > 0) {
          p.node.arguments.forEach((arg, index) => {
            if (isReqInput(arg)) {
              taintedCalls.push({
                callerFile: filePath,
                targetFuncName: funcName,
                taintedIndex: index
              });
            }
          });
        }
      }
    });
  }

  // Phase 3: Identify cross-file loop risks where tainted parameter is used in loop
  analyzeCrossFileHazards() {
    const crossFindings = [];

    for (const call of this.taintedFunctionCalls) {
      const def = this.functionDefinitions.get(call.targetFuncName);
      if (def && def.filePath !== call.callerFile) {
        const taintedParamName = def.params[call.taintedIndex];
        if (taintedParamName) {
          // Check if function body contains a loop multiplying this parameter
          const loopInfo = findLoopUsingParam(def.node, taintedParamName);
          if (loopInfo) {
            crossFindings.push({
              ruleId: 'CROSS_FILE_TAINT_CPU_BOMB',
              severity: 'CRITICAL',
              filePath: def.filePath,
              line: loopInfo.line,
              column: 1,
              route: `Called from ${path.basename(call.callerFile)} → ${def.name}()`,
              snippet: loopInfo.snippet,
              message: `Cross-file taint detected: Function '${def.name}()' executes a heavy loop on parameter '${taintedParamName}' which was passed untrusted request data from '${path.basename(call.callerFile)}'.`,
              attackVector: {
                parameter: taintedParamName,
                exploitValue: 1000,
                description: `Tainted from caller '${path.basename(call.callerFile)}' into service '${path.basename(def.filePath)}'`
              }
            });
          }
        }
      }
    }

    return crossFindings;
  }
}

function isReqInput(node) {
  if (!node) return false;
  if (node.type === 'MemberExpression') {
    if (node.object && (node.object.name === 'req' || node.object.name === 'request')) return true;
    if (isReqInput(node.object)) return true;
  }
  if (node.type === 'Identifier') {
    const name = node.name.toLowerCase();
    return name.includes('factor') || name.includes('size') || name.includes('ticket') || name.includes('limit');
  }
  return false;
}

function findLoopUsingParam(funcNode, paramName) {
  let found = null;
  traverse(funcNode, {
    ForStatement(p) {
      if (found) return;
      if (p.node.test && p.node.test.type === 'BinaryExpression') {
        const code = p.toString ? p.toString() : '';
        if (referencesParam(p.node.test, paramName) && hasMultiplier(p.node.test)) {
          found = {
            line: p.node.loc ? p.node.loc.start.line : 1,
            snippet: `for (...) { // Uses tainted parameter '${paramName}' across files`
          };
        }
      }
    }
  }, { noScope: true });
  return found;
}

function referencesParam(node, paramName) {
  let hasIt = false;
  function walk(n) {
    if (!n || hasIt) return;
    if (n.type === 'Identifier' && n.name === paramName) {
      hasIt = true;
      return;
    }
    for (const key of Object.keys(n)) {
      if (n[key] && typeof n[key] === 'object') walk(n[key]);
    }
  }
  walk(node);
  return hasIt;
}

function hasMultiplier(node) {
  let mult = false;
  function walk(n) {
    if (!n || mult) return;
    if (n.type === 'BinaryExpression' && n.operator === '*') {
      mult = true;
      return;
    }
    for (const key of Object.keys(n)) {
      if (n[key] && typeof n[key] === 'object') walk(n[key]);
    }
  }
  walk(node);
  return mult;
}

