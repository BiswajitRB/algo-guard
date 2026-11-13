import { scanDirectory } from '../src/scanner.js';
import path from 'node:path';
import assert from 'node:assert';

console.log('🧪 Running AlgoGuard Automated Rule Tests...\n');

async function runTests() {
  const fixturesDir = path.resolve('test/fixtures');
  const findings = await scanDirectory(fixturesDir);

  console.log(`Scanned fixtures: found ${findings.length} total findings.\n`);

  // Test 1: clean-controller.js must have 0 findings
  const cleanFindings = findings.filter(f => f.filePath.includes('clean-controller'));
  assert.strictEqual(cleanFindings.length, 0, 'Clean controller should have 0 findings');
  console.log('✅ PASS: Clean controller has 0 false positives.');

  // Test 2: malicious-cpu-bomb.js must detect UNBOUNDED_CPU_LOOP
  const cpuFindings = findings.filter(f => f.filePath.includes('malicious-cpu-bomb'));
  assert.ok(cpuFindings.length > 0, 'CPU bomb must be detected');
  assert.ok(cpuFindings.some(f => f.ruleId === 'UNBOUNDED_CPU_LOOP' || f.ruleId === 'HIGH_COMPLEXITY_MULTIPLIER'));
  console.log('✅ PASS: Malicious CPU bomb accurately detected.');

  // Test 3: malicious-sleep-dos.js must detect sleep/delay
  const sleepFindings = findings.filter(f => f.filePath.includes('malicious-sleep-dos'));
  assert.ok(sleepFindings.length > 0, 'Sleep DoS must be detected');
  assert.ok(sleepFindings.some(f => f.ruleId === 'ARTIFICIAL_THREAD_SLEEP' || f.ruleId === 'HIGH_LATENCY_TIMEOUT'));
  console.log('✅ PASS: Artificial thread sleep DoS accurately detected.');

  // Test 4: malicious-memory-bomb.js must detect UNBOUNDED_MEMORY_ALLOCATION
  const memFindings = findings.filter(f => f.filePath.includes('malicious-memory-bomb'));
  assert.ok(memFindings.length > 0, 'Memory bomb must be detected');
  assert.ok(memFindings.some(f => f.ruleId === 'UNBOUNDED_MEMORY_ALLOCATION'));
  console.log('✅ PASS: Unbounded memory allocation bomb accurately detected.');

  // Test 5: malicious-backdoor.js must detect AUTH_SHORT_CIRCUIT_BACKDOOR
  const backdoorFindings = findings.filter(f => f.filePath.includes('malicious-backdoor'));
  assert.ok(backdoorFindings.length > 0, 'Backdoor must be detected');
  assert.ok(backdoorFindings.some(f => f.ruleId === 'AUTH_SHORT_CIRCUIT_BACKDOOR'));
  console.log('✅ PASS: Hidden auth backdoor accurately detected.');

  console.log('\n🎉 ALL 5 TEST SUITES PASSED PERFECTLY!\n');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
