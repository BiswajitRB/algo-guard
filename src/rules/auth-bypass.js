/**
 * Rule: AUTH_OR_LOGIC_SHORT_CIRCUIT
 * Detects hidden backdoors and auth bypass logic:
 * 1. IfStatement checks comparing raw request parameters to magic keys granting admin/tokens.
 * 2. ConditionalExpression (Ternary ? :) granting elevated privileges based on raw request values.
 */

export function checkAuthBypass(path, filePath, context) {
  const node = path.node;

  // Pattern 1: IfStatement (if (param === 'magic_key') { ... })
  if (path.isIfStatement()) {
    const test = node.test;
    const consequent = node.consequent;

    let grantsPrivilege = false;
    let bypassDetails = null;

    path.get('consequent').traverse({
      CallExpression(innerPath) {
        const callee = innerPath.node.callee;
        if (
          callee.type === 'MemberExpression' &&
          (callee.property.name === 'json' || callee.property.name === 'send')
        ) {
          const arg = innerPath.node.arguments[0];
          if (arg && arg.type === 'ObjectExpression') {
            for (const prop of arg.properties) {
              if (prop.key && (prop.key.name || prop.key.value)) {
                const keyName = String(prop.key.name || prop.key.value).toLowerCase();
                if (isElevatedKeyword(keyName)) {
                  grantsPrivilege = true;
                  bypassDetails = `Returns elevated credentials/role ('${keyName}') directly inside branch`;
                }
              }
            }
          }
        }
      },

      AssignmentExpression(innerPath) {
        const left = innerPath.node.left;
        if (
          left.type === 'MemberExpression' &&
          left.object &&
          (left.object.name === 'req' || left.object.name === 'request')
        ) {
          grantsPrivilege = true;
          bypassDetails = 'Directly assigns authenticated user state on request context';
        }
      }
    });

    if (!grantsPrivilege) return;

    const reqProperty = getTestedRequestProperty(test, path.scope);
    if (reqProperty) {
      context.report({
        ruleId: 'AUTH_SHORT_CIRCUIT_BACKDOOR',
        severity: 'CRITICAL',
        filePath,
        line: node.loc ? node.loc.start.line : 1,
        column: node.loc ? node.loc.start.column : 1,
        snippet: context.getCodeSlice(node),
        message: `Potential backdoor: Condition on '${reqProperty.name}' grants authentication or elevated privilege bypassing regular flow.`,
        attackVector: {
          parameter: reqProperty.name,
          exploitValue: reqProperty.magicValue || 'override_value',
          description: bypassDetails || 'Direct privilege escalation via hidden request parameter.'
        }
      });
    }
  }

  // Pattern 2: ConditionalExpression (Ternary: param === 'secret' ? 'admin' : 'user')
  if (path.isConditionalExpression()) {
    const test = node.test;
    const consequent = node.consequent;
    const alternate = node.alternate;

    const reqProperty = getTestedRequestProperty(test, path.scope);
    if (!reqProperty) return;

    const hasElevatedBranch = isElevatedNode(consequent) || isElevatedNode(alternate);
    if (hasElevatedBranch) {
      context.report({
        ruleId: 'AUTH_SHORT_CIRCUIT_BACKDOOR',
        severity: 'CRITICAL',
        filePath,
        line: node.loc ? node.loc.start.line : 1,
        column: node.loc ? node.loc.start.column : 1,
        snippet: context.getCodeSlice(node),
        message: `Ternary backdoor detected: Parameter '${reqProperty.name}' directly assigns elevated role or privileges via conditional expression.`,
        attackVector: {
          parameter: reqProperty.name,
          exploitValue: reqProperty.magicValue || 'secret_override',
          description: 'Ternary expression short-circuits privilege assignment.'
        }
      });
    }
  }
}

function isElevatedKeyword(str) {
  return (
    str.includes('role') ||
    str.includes('admin') ||
    str.includes('token') ||
    str.includes('authenticated') ||
    str.includes('auth') ||
    str.includes('root')
  );
}

function isElevatedNode(node) {
  if (!node) return false;
  if (node.type === 'StringLiteral') {
    const val = node.value.toLowerCase();
    return val === 'admin' || val === 'root' || val === 'superuser';
  }
  if (node.type === 'ObjectExpression') {
    for (const prop of node.properties) {
      if (prop.key && isElevatedKeyword(String(prop.key.name || prop.key.value).toLowerCase())) {
        return true;
      }
    }
  }
  return false;
}

function getTestedRequestProperty(node, scope) {
  if (!node) return null;

  if (node.type === 'BinaryExpression') {
    if (isUntrustedOrIdentifier(node.left, scope) && isLiteral(node.right)) {
      return {
        name: extractName(node.left),
        magicValue: node.right.value
      };
    }
    if (isUntrustedOrIdentifier(node.right, scope) && isLiteral(node.left)) {
      return {
        name: extractName(node.right),
        magicValue: node.left.value
      };
    }
  }

  if (isUntrustedOrIdentifier(node, scope)) {
    return {
      name: extractName(node),
      magicValue: true
    };
  }

  return null;
}

function isLiteral(node) {
  return node && (node.type === 'StringLiteral' || node.type === 'BooleanLiteral' || node.type === 'NumericLiteral');
}

function isUntrustedOrIdentifier(n, scope) {
  if (!n) return false;
  if (isReqMember(n)) return true;

  if (n.type === 'Identifier') {
    if (scope && scope.getBinding) {
      const binding = scope.getBinding(n.name);
      if (binding && binding.path) {
        const init = binding.path.node.init;
        if (init && isReqMember(init)) return true;
        const parent = binding.path.parent;
        if (parent && parent.declarations) {
          for (const decl of parent.declarations) {
            if (decl.init && isReqMember(decl.init)) return true;
          }
        }
      }
    }
    return true;
  }

  return false;
}

function isReqMember(n) {
  if (!n) return false;
  if (n.type === 'MemberExpression') {
    if (n.object && (n.object.name === 'req' || n.object.name === 'request')) return true;
    if (n.object && isReqMember(n.object)) return true;
  }
  return false;
}

function extractName(n) {
  if (!n) return 'flag';
  if (n.type === 'Identifier') return n.name;
  if (n.type === 'MemberExpression' && n.property && n.property.name) {
    return n.property.name;
  }
  return 'auth_override';
}
