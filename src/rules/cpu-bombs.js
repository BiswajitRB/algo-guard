/**
 * Rule: UNBOUNDED_CPU_LOOP & BUSY_WAIT
 * Detects algorithmic CPU exhaustion:
 * 1. Loops with bounds multiplied by user request input.
 * 2. Excessively high static loop bounds (> 50,000 iterations) in request paths.
 * 3. Busy-wait spin loops (e.g., while(Date.now() < ...)).
 */

export function checkCpuBombs(path, filePath, context) {
  const node = path.node;

  // 1. Check ForStatement / WhileStatement
  if (path.isForStatement() || path.isWhileStatement() || path.isDoWhileStatement()) {
    const test = node.test;
    if (!test) return;

    // Pattern 1A: Loop bounded by expression multiplying user input
    // e.g., i < factor * 100000 or i < req.body.count
    if (test.type === 'BinaryExpression') {
      const right = test.right;
      const left = test.left;

      // Check if either side references a request property or multiplier
      const isMultiplicationWithHighConstant = 
        (right.type === 'BinaryExpression' && right.operator === '*' && hasLargeNumber(right)) ||
        (left.type === 'BinaryExpression' && left.operator === '*' && hasLargeNumber(left));

      const referencesUserInput = referencesRequestInput(test);

      if (isMultiplicationWithHighConstant && referencesUserInput) {
        context.report({
          ruleId: 'UNBOUNDED_CPU_LOOP',
          severity: 'CRITICAL',
          filePath,
          line: node.loc ? node.loc.start.line : 1,
          column: node.loc ? node.loc.start.column : 1,
          snippet: context.getCodeSlice(node),
          message: 'Loop condition multiplies request input with an extreme factor. High risk of 100% CPU lockup / DoS.',
          attackVector: {
            parameter: extractParamName(test) || 'payload_factor',
            exploitValue: 1000,
            description: 'Sending a high numeric value will force the server into an astronomical number of iterations.'
          }
        });
        return;
      }

      if (isMultiplicationWithHighConstant) {
        context.report({
          ruleId: 'HIGH_COMPLEXITY_MULTIPLIER',
          severity: 'HIGH',
          filePath,
          line: node.loc ? node.loc.start.line : 1,
          column: node.loc ? node.loc.start.column : 1,
          snippet: context.getCodeSlice(node),
          message: 'Loop uses a massive iteration multiplier (>50,000). Risk of request timeout and CPU exhaustion.'
        });
        return;
      }

      // Pattern 1B: Pure huge constant in loop condition (> 100,000)
      if (right.type === 'NumericLiteral' && right.value >= 100000) {
        context.report({
          ruleId: 'EXTREME_ITERATION_BOUND',
          severity: 'HIGH',
          filePath,
          line: node.loc ? node.loc.start.line : 1,
          column: node.loc ? node.loc.start.column : 1,
          snippet: context.getCodeSlice(node),
          message: `Loop bounds statically set to ${right.value.toLocaleString()} iterations inside execution path.`
        });
        return;
      }
    }

    // Pattern 1C: Busy-wait loop (e.g., while (Date.now() < target))
    if (isBusyWait(test)) {
      context.report({
        ruleId: 'BUSY_WAIT_SPIN_LOOP',
        severity: 'CRITICAL',
        filePath,
        line: node.loc ? node.loc.start.line : 1,
        column: node.loc ? node.loc.start.column : 1,
        snippet: context.getCodeSlice(node),
        message: 'Busy-wait spin loop detected (Date.now/performance.now). Monopolizes CPU core and blocks the event loop.'
      });
    }
  }
}

function hasLargeNumber(node) {
  if (!node) return false;
  if (node.type === 'NumericLiteral' && node.value >= 10000) return true;
  if (node.left && hasLargeNumber(node.left)) return true;
  if (node.right && hasLargeNumber(node.right)) return true;
  return false;
}

function referencesRequestInput(node) {
  let found = false;
  function walk(n) {
    if (!n || found) return;
    // req.body.x, req.query.x, req.params.x or common parameter aliases
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
      if (name.includes('factor') || name.includes('count') || name.includes('iterations') || name.includes('multiplier')) {
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

function extractParamName(node) {
  let name = null;
  function walk(n) {
    if (!n || name) return;
    if (n.type === 'MemberExpression' && n.property && n.property.name) {
      name = n.property.name;
      return;
    }
    if (n.type === 'Identifier') {
      const id = n.name;
      if (id !== 'i' && id !== 'j' && id !== 'k' && id !== 'index' && id !== 'len' && id !== 'length') {
        name = id;
        return;
      }
    }
    for (const key of Object.keys(n)) {
      if (n[key] && typeof n[key] === 'object') walk(n[key]);
    }
  }
  walk(node);
  return name || 'factor';
}

function isBusyWait(node) {
  if (!node) return false;
  let hasDateNow = false;
  function walk(n) {
    if (!n || hasDateNow) return;
    if (
      n.type === 'CallExpression' &&
      n.callee &&
      n.callee.type === 'MemberExpression' &&
      n.callee.object &&
      n.callee.object.name === 'Date' &&
      n.callee.property &&
      n.callee.property.name === 'now'
    ) {
      hasDateNow = true;
      return;
    }
    for (const key of Object.keys(n)) {
      if (n[key] && typeof n[key] === 'object') walk(n[key]);
    }
  }
  walk(node);
  return hasDateNow;
}
