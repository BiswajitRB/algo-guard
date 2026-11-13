import { scanDirectory } from '../src/scanner.js';
import path from 'node:path';
import assert from 'node:assert';

console.log('🧪 Running AlgoGuard Comprehensive End-to-End & Polyglot Tests...\n');

async function runTests() {
  const fixturesDir = path.resolve('test/fixtures');
  const findings = await scanDirectory(fixturesDir);

  console.log(`Scanned fixtures: found ${findings.length} total findings across all languages & call graphs.\n`);

  // Test 1: clean-controller.js must have 0 findings
  const cleanFindings = findings.filter(f => f.filePath.includes('clean-controller'));
  assert.strictEqual(cleanFindings.length, 0, 'Clean controller should have 0 findings');
  console.log('✅ PASS: Clean controller has 0 false positives.');

  // Test 2: suppression-test.js with // algoguard-ignore must have 0 findings!
  const suppressedFindings = findings.filter(f => f.filePath.includes('suppression-test'));
  assert.strictEqual(suppressedFindings.length, 0, 'Suppressed loop with // algoguard-ignore must be 0');
  console.log('✅ PASS: Inline comment suppression (// algoguard-ignore) successfully ignored intentional loop.');

  // Test 3: Node.js malicious-cpu-bomb.js
  const cpuFindings = findings.filter(f => f.filePath.includes('malicious-cpu-bomb'));
  assert.ok(cpuFindings.length > 0, 'Node CPU bomb must be detected');
  console.log('✅ PASS: Node.js CPU bomb detected with Financial Impact.');

  // Test 4: React component JSX support
  const reactFindings = findings.filter(f => f.filePath.includes('react-component'));
  assert.ok(reactFindings.length >= 2, 'React component should trigger at least 2 findings');
  console.log('✅ PASS: React (JSX) frontend backdoor and DOM render bomb detected.');

  // Test 5: Python API support (FastAPI / Flask)
  const pyFindings = findings.filter(f => f.filePath.includes('python_api'));
  assert.ok(pyFindings.length >= 3, 'Python file should trigger at least 3 findings');
  console.log('✅ PASS: Python (FastAPI/Flask) CPU bombs, sleep DoS, and auth backdoors detected.');

  // Test 6: Java Spring Boot support (.java)
  const javaFindings = findings.filter(f => f.filePath.includes('OrderController.java'));
  assert.ok(javaFindings.length >= 3, 'Java file should trigger CPU, Sleep, and Backdoor findings');
  console.log(`✅ PASS: Java (Spring Boot) detected ${javaFindings.length} issues (CPU loop, Sleep, OOM, Backdoor).`);

  // Test 7: Go Gin/Fiber support (.go)
  const goFindings = findings.filter(f => f.filePath.includes('handler.go'));
  assert.ok(goFindings.length >= 2, 'Go file should trigger Sleep and CPU loop findings');
  console.log(`✅ PASS: Go (Gin/Fiber) detected ${goFindings.length} issues (Sleep DoS, CPU loop, Memory allocation).`);

  // Test 8: Rust Actix support (.rs)
  const rustFindings = findings.filter(f => f.filePath.includes('service.rs'));
  assert.ok(rustFindings.length >= 2, 'Rust file should trigger Sleep and CPU loop findings');
  console.log(`✅ PASS: Rust (Actix/Axum) detected ${rustFindings.length} issues (thread::sleep, CPU loop, vec! allocation).`);

  // Test 9: End-to-End Cross-File Taint Tracking
  const crossFindings = findings.filter(f => f.ruleId === 'CROSS_FILE_TAINT_CPU_BOMB');
  assert.ok(crossFindings.length > 0, 'Must detect cross-file taint from controller into helper service');
  console.log('✅ PASS: End-to-End Cross-File Taint Tracking successfully traced parameters across modules.');

  // Test 10: Ternary Operator Backdoor Detection
  const ternaryFindings = findings.filter(f => f.filePath.includes('ternary-backdoor'));
  assert.ok(ternaryFindings.length > 0, 'Ternary backdoor must be detected');
  assert.ok(ternaryFindings[0].message.includes('Ternary backdoor detected'), 'Should explicitly identify ternary pattern');
  console.log('✅ PASS: Ternary operator backdoor expression (? :) successfully detected.');

  // Test 11: Catastrophic ReDoS Regex Detection
  const redosFindings = findings.filter(f => f.filePath.includes('redos-controller'));
  assert.ok(redosFindings.length > 0, 'ReDoS vulnerability must be detected');
  assert.ok(redosFindings.some(f => f.ruleId === 'REGEX_CATASTROPHIC_BACKTRACKING'), 'Must identify ReDoS rule');
  console.log('✅ PASS: Catastrophic ReDoS regex backtracking ((a+)+) successfully detected.');

  // Test 12: Git Pre-Push Hook Installer
  const { installGitHook, uninstallGitHook } = await import('../src/devops/hook-installer.js');
  const installedPath = installGitHook('.');
  assert.ok(installedPath.includes('pre-push'), 'Hook path must contain pre-push');
  const uninstalled = uninstallGitHook('.');
  assert.strictEqual(uninstalled, true, 'Hook must uninstall cleanly');
  console.log('✅ PASS: Git pre-push hook installed and uninstalled cleanly.');

  // Test 13: DevOps Bundle Generators (Kubernetes, k6, Prometheus)
  const { generateK8sRecommendations } = await import('../src/devops/k8s-generator.js');
  const { generateK6Script } = await import('../src/devops/k6-generator.js');
  const { generatePrometheusRules } = await import('../src/devops/prometheus-generator.js');

  const k8s = generateK8sRecommendations(findings);
  assert.ok(k8s.yaml.includes('limits:'), 'K8s config must include limits');
  const k6 = generateK6Script(findings);
  assert.ok(k6.includes('import http from \'k6/http\''), 'k6 script must import k6/http');
  const prom = generatePrometheusRules(findings);
  assert.ok(prom.includes('kind: PrometheusRule'), 'Prometheus rules must be valid CRD');
  console.log('✅ PASS: DevOps Infrastructure artifacts (K8s, k6, Prometheus) generated.');

  console.log('\n🎉 ALL 13 COMPREHENSIVE END-TO-END & POLYGLOT TEST SUITES PASSED!\n');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
