/**
 * Rule: AUTH_OR_LOGIC_SHORT_CIRCUIT
 * Detects hidden backdoors and auth bypass logic:
 * 1. Checks if a request parameter (query/body/header, including destructured vars)
 *    directly grants admin/tokens/privileges or returns early bypassing database authentication.
 * 2. Compares inputs against hardcoded backdoor magic tokens/keys.
 */

export function checkAuthBypass(path, filePath, context) {
  const node = path.node;

  if (path.isIfStatement()) {
    const test = node.test;
    const consequent = node.consequent;

    // First inspect what happens inside the 'if' block (consequent)
    let grantsPrivilege = false;
    let bypassDetails = null;

    path.get('consequent').traverse({
      // Look for response sending back tokens or admin roles
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
                if (
                  keyName.includes('role') ||
                  keyName.includes('admin') ||
                  keyName.includes('token') ||
                  keyName.includes('authenticated') ||
                  keyName.includes('auth')
                ) {
                  grantsPrivilege = true;
                  bypassDetails = `Returns elevated credentials/role ('${keyName}') directly inside branch`;
                }
              }
            }
          }
        }
      },

      // Look for assignment like req.user = { role: 'admin' }
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

    // Check if the condition evaluates a request property or string literal comparison
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
}

function getTestedRequestProperty(node, scope) {
  if (!node) return null;

  // Pattern: x === "some_secret_key"
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

  // Pattern: if (req.body.override) or if (is_admin_override)
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
  // Direct req.body.x
  if (isReqMember(n)) return true;

  // Identifier that was destructured from req or declared locally
  if (n.type === 'Identifier') {
    if (scope && scope.getBinding) {
      const binding = scope.getBinding(n.name);
      if (binding && binding.path) {
        const init = binding.path.node.init;
        if (init && isReqMember(init)) return true;
        // Check pattern: const { ticket } = req.body
        const parent = binding.path.parent;
        if (parent && parent.declarations) {
          for (const decl of parent.declarations) {
            if (decl.init && isReqMember(decl.init)) return true;
          }
        }
      }
    }
    // Any identifier compared to a secret literal before returning elevated tokens
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
