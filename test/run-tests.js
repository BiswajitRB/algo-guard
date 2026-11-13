import { scanDirectory } from '../src/scanner.js';
import path from 'node:path';
import assert from 'node:assert';

console.log('🧪 Running AlgoGuard Automated Multi-Language Tests (Node.js, React, Python)...\n');

async function runTests() {
  const fixturesDir = path.resolve('test/fixtures');
  const findings = await scanDirectory(fixturesDir);

  console.log(`Scanned fixtures: found ${findings.length} total findings across all languages.\n`);

  // Test 1: clean-controller.js must have 0 findings
  const cleanFindings = findings.filter(f => f.filePath.includes('clean-controller'));
  assert.strictEqual(cleanFindings.length, 0, 'Clean controller should have 0 findings');
  console.log('✅ PASS: Clean controller has 0 false positives.');

  // Test 2: Node.js malicious-cpu-bomb.js
  const cpuFindings = findings.filter(f => f.filePath.includes('malicious-cpu-bomb'));
  assert.ok(cpuFindings.length > 0, 'Node CPU bomb must be detected');
  assert.ok(cpuFindings[0].cloudImpact, 'Must include Cloud Cost Impact');
  console.log('✅ PASS: Node.js CPU bomb detected with Financial Impact.');

  // Test 3: Node.js malicious-sleep-dos.js
  const sleepFindings = findings.filter(f => f.filePath.includes('malicious-sleep-dos'));
  assert.ok(sleepFindings.length > 0, 'Node Sleep DoS must be detected');
  console.log('✅ PASS: Node.js Artificial thread sleep DoS detected.');

  // Test 4: Node.js malicious-memory-bomb.js
  const memFindings = findings.filter(f => f.filePath.includes('malicious-memory-bomb'));
  assert.ok(memFindings.length > 0, 'Node Memory bomb must be detected');
  console.log('✅ PASS: Node.js Unbounded memory allocation detected.');

  // Test 5: Node.js malicious-backdoor.js
  const backdoorFindings = findings.filter(f => f.filePath.includes('malicious-backdoor'));
  assert.ok(backdoorFindings.length > 0, 'Node Backdoor must be detected');
  console.log('✅ PASS: Node.js Hidden auth backdoor detected.');

  // Test 6: React component JSX support
  const reactFindings = findings.filter(f => f.filePath.includes('react-component'));
  assert.ok(reactFindings.length >= 2, 'React component should trigger at least 2 findings');
  assert.ok(reactFindings.some(f => f.ruleId === 'FRONTEND_BACKDOOR_CALL'), 'Should catch frontend backdoor call');
  assert.ok(reactFindings.some(f => f.ruleId === 'UNBOUNDED_DOM_RENDER_BOMB'), 'Should catch DOM render bomb');
  console.log('✅ PASS: React (JSX) frontend backdoor and DOM render bomb detected.');

  // Test 7: Python API support (FastAPI / Flask)
  const pyFindings = findings.filter(f => f.filePath.includes('python_api'));
  assert.ok(pyFindings.length >= 3, 'Python file should trigger at least 3 findings');
  assert.ok(pyFindings.some(f => f.ruleId === 'UNBOUNDED_CPU_LOOP'), 'Python range multiplier detected');
  assert.ok(pyFindings.some(f => f.ruleId === 'ARTIFICIAL_THREAD_SLEEP'), 'Python time.sleep detected');
  assert.ok(pyFindings.some(f => f.ruleId === 'AUTH_SHORT_CIRCUIT_BACKDOOR'), 'Python auth backdoor detected');
  console.log('✅ PASS: Python (FastAPI/Flask) CPU bombs, sleep DoS, and auth backdoors detected.');

  console.log('\n🎉 ALL 7 MULTI-LANGUAGE TEST SUITES PASSED PERFECTLY!\n');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
