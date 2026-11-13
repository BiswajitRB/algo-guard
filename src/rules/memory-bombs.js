/**
 * Rule: UNBOUNDED_MEMORY_ALLOCATION
 * Detects memory exhaustion bombs:
 * 1. Buffer.alloc / Buffer.allocUnsafe with size derived from request or > 50MB.
 * 2. Array(size) or string.repeat(size) with high bounds.
 */

export function checkMemoryBombs(path, filePath, context) {
  const node = path.node;

  // Pattern 3A: Buffer.alloc / Buffer.allocUnsafe
  if (path.isCallExpression()) {
    const callee = node.callee;
    if (
      callee.type === 'MemberExpression' &&
      callee.object &&
      callee.object.name === 'Buffer' &&
      callee.property &&
      (callee.property.name === 'alloc' || callee.property.name === 'allocUnsafe')
    ) {
      const sizeArg = node.arguments[0];
      const isFromInput = referencesRequestInput(sizeArg);
      const isHighMultiplier = hasHighMultiplier(sizeArg);

      if (isFromInput && isHighMultiplier) {
        context.report({
          ruleId: 'UNBOUNDED_MEMORY_ALLOCATION',
          severity: 'CRITICAL',
          filePath,
          line: node.loc ? node.loc.start.line : 1,
          column: node.loc ? node.loc.start.column : 1,
          snippet: context.getCodeSlice(node),
          message: 'Buffer allocation size is multiplied directly from request input. An attacker can force immediate Node.js OOM (Out Of Memory) crash.',
          attackVector: {
            parameter: 'size_multiplier',
            exploitValue: 1024,
            description: 'Passing a large chunk size will trigger Node.js ERR_BUFFER_TOO_LARGE or process SIGKILL/OOM.'
          }
        });
        return;
      }
    }

    // Pattern 3B: string.repeat(size) with request input or large factor
    if (
      callee.type === 'MemberExpression' &&
      callee.property &&
      callee.property.name === 'repeat'
    ) {
      const repeatArg = node.arguments[0];
      if (referencesRequestInput(repeatArg) || (repeatArg.type === 'NumericLiteral' && repeatArg.value > 1000000)) {
        context.report({
          ruleId: 'STRING_EXPANSION_BOMB',
          severity: 'HIGH',
          filePath,
          line: node.loc ? node.loc.start.line : 1,
          column: node.loc ? node.loc.start.column : 1,
          snippet: context.getCodeSlice(node),
          message: 'String repeat expansion size derived from untrusted input or excessive constant (>1MB).'
        });
      }
    }
  }

  // Pattern 3C: new Array(hugeSize)
  if (path.isNewExpression() && node.callee.name === 'Array') {
    const sizeArg = node.arguments[0];
    if (sizeArg && (referencesRequestInput(sizeArg) || (sizeArg.type === 'NumericLiteral' && sizeArg.value > 1000000))) {
      context.report({
        ruleId: 'ARRAY_ALLOCATION_BOMB',
        severity: 'HIGH',
        filePath,
        line: node.loc ? node.loc.start.line : 1,
        column: node.loc ? node.loc.start.column : 1,
        snippet: context.getCodeSlice(node),
        message: 'Unbounded array allocation sizing. Can crash the V8 heap.'
      });
    }
  }
}

function referencesRequestInput(node) {
  if (!node) return false;
  let found = false;
  function walk(n) {
    if (!n || found) return;
    if (n.type === 'MemberExpression') {
      const obj = n.object;
      const prop = n.property;
      if (
        (obj.name === 'req' || obj.name === 'request') &&
        (prop.name === 'body' || prop.name === 'query' || prop.name === 'params' || prop.name === 'headers')
      ) {
        found = true;
        return;
      }
    }
    if (n.type === 'Identifier') {
      const name = n.name.toLowerCase();
      if (name.includes('size') || name.includes('chunk') || name.includes('length') || name.includes('buffer')) {
        found = true;
        return;
      }
    }
    for (const key of Object.keys(n)) {
      if (n[key] && typeof n[key] === 'object') walk(n[key]);
    }
  }
  walk(node);
  return found;
}

function hasHighMultiplier(node) {
  if (!node) return false;
  if (node.type === 'BinaryExpression' && node.operator === '*') {
    if (
      (node.right && node.right.type === 'NumericLiteral' && node.right.value >= 1024) ||
      (node.left && node.left.type === 'NumericLiteral' && node.left.value >= 1024)
    ) {
      return true;
    }
  }
  return false;
}

