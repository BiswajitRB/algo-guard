/**
 * Rule: REGEX_CATASTROPHIC_BACKTRACKING (ReDoS)
 * Detects exponential and polynomial catastrophic backtracking patterns:
 * 1. Nested quantifiers: (a+)+, ([a-z]+)*, (\d+)+
 * 2. Overlapping alternations with quantifiers: (a|aa)+, (.*a)+
 * 3. Quantified wildcards inside repeated groups.
 */

// Common catastrophic ReDoS signatures
const NESTED_QUANTIFIER_REGEX = /\((?:[^()\\]|\\.)*[+*]\s*\)[+*]/;
const REPEATED_OVERLAPPING_GROUP = /\((?:[a-zA-Z0-9_\-.]+[|&])+.*?\)[+*]/;
const UNBOUNDED_WILDCARD_REPEAT = /\(\.\*[a-zA-Z0-9]+\)[+*]/;

export function checkReDosBombs(path, filePath, context) {
  const node = path.node;
  let pattern = null;
  let rawFlags = '';

  // 1. Literal RegExp: /([a-z]+)+/g
  if (path.isRegExpLiteral()) {
    pattern = node.pattern;
    rawFlags = node.flags || '';
  }

  // 2. new RegExp("([a-z]+)+", "g")
  if (path.isNewExpression() && node.callee.name === 'RegExp') {
    const firstArg = node.arguments[0];
    if (firstArg && firstArg.type === 'StringLiteral') {
      pattern = firstArg.value;
    }
  }

  if (!pattern) return;

  const redosVulnerability = inspectPattern(pattern);
  if (redosVulnerability) {
    context.report({
      ruleId: 'REGEX_CATASTROPHIC_BACKTRACKING',
      severity: 'CRITICAL',
      filePath,
      line: node.loc ? node.loc.start.line : 1,
      column: node.loc ? node.loc.start.column : 1,
      snippet: context.getCodeSlice(node),
      message: `Catastrophic ReDoS vulnerability detected in regex /${pattern}/${rawFlags}. Pattern exhibits ${redosVulnerability.type} which freezes CPU for minutes on non-matching payloads.`,
      attackVector: {
        parameter: 'regex_input_payload',
        exploitValue: redosVulnerability.exploitPayload,
        description: `Sending '${redosVulnerability.exploitPayload}' triggers exponential backtracking (100% CPU freeze).`
      }
    });
  }
}

export function inspectPattern(pattern) {
  if (NESTED_QUANTIFIER_REGEX.test(pattern)) {
    return {
      type: 'nested quantifier exponential backtracking (e.g. (a+)+)',
      exploitPayload: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!'
    };
  }

  if (REPEATED_OVERLAPPING_GROUP.test(pattern)) {
    return {
      type: 'overlapping alternation repeat (e.g. (a|aa)+)',
      exploitPayload: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!'
    };
  }

  if (UNBOUNDED_WILDCARD_REPEAT.test(pattern)) {
    return {
      type: 'unbounded wildcard repetition (e.g. (.*a)+)',
      exploitPayload: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!'
    };
  }

  return null;
}
