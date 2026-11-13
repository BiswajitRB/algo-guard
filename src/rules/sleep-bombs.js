/**
 * Rule: ARTIFICIAL_THREAD_SLEEP
 * Detects artificial latency or thread sleep/delays:
 * 1. Synchronous sleep loops or blocking sleep calls.
 * 2. Asynchronous delays (setTimeout, delay(), sleep(ms)) with high duration (> 2,000ms)
 *    inside HTTP request handlers, which silently starve server workers.
 */

export function checkSleepBombs(path, filePath, context) {
  const node = path.node;

  if (path.isCallExpression()) {
    const callee = node.callee;

    // Pattern 2A: Direct call to sleep(...) or thread.sleep(...)
    const isDirectSleep =
      (callee.type === 'Identifier' && callee.name.toLowerCase() === 'sleep') ||
      (callee.type === 'MemberExpression' &&
        callee.property &&
        callee.property.name &&
        callee.property.name.toLowerCase() === 'sleep');

    if (isDirectSleep) {
      const arg = node.arguments[0];
      const durationMs = extractNumericValue(arg);

      context.report({
        ruleId: 'ARTIFICIAL_THREAD_SLEEP',
        severity: 'CRITICAL',
        filePath,
        line: node.loc ? node.loc.start.line : 1,
        column: node.loc ? node.loc.start.column : 1,
        snippet: context.getCodeSlice(node),
        message: `Explicit sleep call detected${durationMs ? ` (~${durationMs}ms)` : ''}. In web request handlers, this causes worker thread starvation and artificial latency DoS.`,
        attackVector: {
          parameter: 'trigger_condition',
          exploitValue: true,
          description: 'Invoking this handler will hold server connection pools open, leading to gateway timeouts (504).'
        }
      });
      return;
    }

    // Pattern 2B: setTimeout / setInterval with long delay inside handler (> 3,000ms)
    if (callee.type === 'Identifier' && (callee.name === 'setTimeout' || callee.name === 'setInterval')) {
      const delayArg = node.arguments[1];
      const delayMs = extractNumericValue(delayArg);

      if (delayMs && delayMs >= 3000) {
        context.report({
          ruleId: 'HIGH_LATENCY_TIMEOUT',
          severity: 'HIGH',
          filePath,
          line: node.loc ? node.loc.start.line : 1,
          column: node.loc ? node.loc.start.column : 1,
          snippet: context.getCodeSlice(node),
          message: `${callee.name} configured with high delay (${delayMs}ms) in execution path. Potential stealth delay attack.`
        });
        return;
      }
    }

    // Pattern 2C: Promise delay helper (new Promise(res => setTimeout(res, ms)))
    if (path.isNewExpression() && callee.name === 'Promise') {
      const argFunc = node.arguments[0];
      if (argFunc && (argFunc.type === 'ArrowFunctionExpression' || argFunc.type === 'FunctionExpression')) {
        let hasTimeout = false;
        path.traverse({
          CallExpression(innerPath) {
            if (innerPath.node.callee && innerPath.node.callee.name === 'setTimeout') {
              const ms = extractNumericValue(innerPath.node.arguments[1]);
              if (ms && ms >= 2000) {
                hasTimeout = true;
                context.report({
                  ruleId: 'ARTIFICIAL_ASYNC_DELAY',
                  severity: 'HIGH',
                  filePath,
                  line: node.loc ? node.loc.start.line : 1,
                  column: node.loc ? node.loc.start.column : 1,
                  snippet: context.getCodeSlice(node),
                  message: `Async sleep/delay Promise detected (${ms}ms). Can be exploited to exhaust server socket limits.`
                });
              }
            }
          }
        });
      }
    }
  }
}

function extractNumericValue(node) {
  if (!node) return null;
  if (node.type === 'NumericLiteral') return node.value;
  if (node.type === 'BinaryExpression' && node.operator === '*') {
    const left = extractNumericValue(node.left);
    const right = extractNumericValue(node.right);
    if (left !== null && right !== null) return left * right;
  }
  return null;
}

