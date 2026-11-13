import fs from 'node:fs';
import path from 'node:path';

export function installGitHook(targetDir = '.') {
  const gitDir = findGitDir(targetDir);
  if (!gitDir) {
    throw new Error('No .git directory found. Please run this inside a git repository.');
  }

  const hooksDir = path.join(gitDir, 'hooks');
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const prePushPath = path.join(hooksDir, 'pre-push');

  const hookContent = `#!/bin/sh
# 🛡️ AlgoGuard Pre-Push Hook
# Automatically blocks pushes containing critical CPU bombs, sleep DoS, or auth backdoors.

echo "🛡️  AlgoGuard: Auditing code for algorithmic hazards before push..."

# Run AlgoGuard scanner with fail-on-risk enabled
if command -v node >/dev/null 2>&1; then
  if [ -f "bin/algo-guard.js" ]; then
    node bin/algo-guard.js scan --fail-on-risk
  else
    npx --yes algo-guard scan --fail-on-risk
  fi
else
  echo "⚠️ Node.js not detected in PATH, skipping local AlgoGuard check."
  exit 0
fi

RESULT=$?

if [ $RESULT -ne 0 ]; then
  echo ""
  echo "❌ Push blocked by AlgoGuard! Fix the detected hazards above before pushing."
  echo "💡 Emergency override: git push --no-verify"
  echo ""
  exit 1
fi

echo "✅ AlgoGuard: Code audit passed cleanly. Pushing to remote..."
exit 0
`;

  fs.writeFileSync(prePushPath, hookContent, { encoding: 'utf-8', mode: 0o755 });
  try {
    fs.chmodSync(prePushPath, 0o755);
  } catch {}

  return prePushPath;
}

export function uninstallGitHook(targetDir = '.') {
  const gitDir = findGitDir(targetDir);
  if (!gitDir) return false;

  const prePushPath = path.join(gitDir, 'hooks', 'pre-push');
  if (fs.existsSync(prePushPath)) {
    fs.unlinkSync(prePushPath);
    return true;
  }
  return false;
}

function findGitDir(startDir) {
  let curr = path.resolve(startDir);
  while (curr !== path.parse(curr).root) {
    const candidate = path.join(curr, '.git');
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    curr = path.dirname(curr);
  }
  return null;
}
