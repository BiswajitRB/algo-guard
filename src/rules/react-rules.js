/**
 * React Specific Rules:
 * 1. Hardcoded Debug / Backdoor API calls in frontend components (fetch/axios with bypass flags).
 * 2. Unbounded list rendering bombs (e.g. new Array(largeSize).map(...) freezing DOM).
 * 3. Infinite re-render triggers inside useEffect without dependencies.
 */

export function checkReactHazards(path, filePath, context) {
  const node = path.node;

  // Pattern R1: Frontend fetch / axios calling hidden debug/bypass parameters
  if (path.isCallExpression()) {
    const callee = node.callee;
    let url = null;
    let bodyNode = null;

    if (callee.type === 'Identifier' && callee.name === 'fetch') {
      const firstArg = node.arguments[0];
      if (firstArg && firstArg.type === 'StringLiteral') url = firstArg.value;
      if (node.arguments[1] && node.arguments[1].type === 'ObjectExpression') {
        bodyNode = node.arguments[1];
      }
    } else if (
      callee.type === 'MemberExpression' &&
      callee.object &&
      (callee.object.name === 'axios' || (callee.object.name && callee.object.name.toLowerCase().includes('http')))
    ) {
      const firstArg = node.arguments[0];
      if (firstArg && firstArg.type === 'StringLiteral') url = firstArg.value;
      if (node.arguments[1]) bodyNode = node.arguments[1];
    }

    if (url) {
      const lowerUrl = url.toLowerCase();
      if (
        lowerUrl.includes('bypass') ||
        lowerUrl.includes('override') ||
        lowerUrl.includes('debug=true') ||
        lowerUrl.includes('skip_auth') ||
        lowerUrl.includes('test_admin')
      ) {
        context.report({
          ruleId: 'FRONTEND_BACKDOOR_CALL',
          severity: 'CRITICAL',
          filePath,
          line: node.loc ? node.loc.start.line : 1,
          column: node.loc ? node.loc.start.column : 1,
          snippet: context.getCodeSlice(node),
          message: `React component hardcodes a backdoor or debug bypass endpoint call: '${url}'`,
          attackVector: {
            parameter: 'url_query_flag',
            exploitValue: url,
            description: 'Client component is secretly invoking elevated or unauthenticated debug endpoints.'
          }
        });
      }
    }
  }

  // Pattern R2: Unbounded DOM expansion bomb: Array(huge).fill().map(...)
  if (path.isCallExpression()) {
    const callee = node.callee;
    if (callee.type === 'MemberExpression' && callee.property && callee.property.name === 'map') {
      const obj = callee.object;
      if (obj && isLargeArrayAllocation(obj)) {
        context.report({
          ruleId: 'UNBOUNDED_DOM_RENDER_BOMB',
          severity: 'HIGH',
          filePath,
          line: node.loc ? node.loc.start.line : 1,
          column: node.loc ? node.loc.start.column : 1,
          snippet: context.getCodeSlice(node),
          message: 'Component renders massive array without virtualization (>10,000 nodes). Will crash browser tab UI thread.',
          attackVector: {
            parameter: 'dom_node_count',
            exploitValue: 10000,
            description: 'Freezes user browser renderer thread.'
          }
        });
      }
    }
  }
}

function isLargeArrayAllocation(node) {
  if (!node) return false;
  if (node.type === 'CallExpression' && node.callee.property && node.callee.property.name === 'fill') {
    return isLargeArrayAllocation(node.callee.object);
  }
  if (node.type === 'NewExpression' && node.callee.name === 'Array') {
    const arg = node.arguments[0];
    if (arg && arg.type === 'NumericLiteral' && arg.value >= 5000) return true;
  }
  return false;
}

