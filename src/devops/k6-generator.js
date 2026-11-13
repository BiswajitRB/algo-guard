/**
 * Generates an executable k6 load-testing script targeting the detected endpoints.
 * DevOps engineers can run this in CI or staging to verify if clusters can handle the load.
 */

export function generateK6Script(findings, targetBaseUrl = 'http://localhost:3000') {
  const requests = [];

  findings.forEach(f => {
    if (!f.route || !f.attackVector) return;
    const parts = f.route.split(' ');
    const method = parts.length > 1 ? parts[0] : 'POST';
    const path = parts.length > 1 ? parts[1] : (typeof f.attackVector.exploitValue === 'string' && f.attackVector.exploitValue.startsWith('/') ? f.attackVector.exploitValue : '/api');

    const payload = JSON.stringify({
      [f.attackVector.parameter]: f.attackVector.exploitValue
    });

    requests.push({
      rule: f.ruleId,
      method,
      path,
      payload
    });
  });

  if (requests.length === 0) {
    requests.push({
      rule: 'BASELINE_CHECK',
      method: 'GET',
      path: '/healthz',
      payload: '{}'
    });
  }

  const script = `// 🛡️ Auto-generated k6 load testing script by AlgoGuard
// Run with: k6 run algoguard-k6-stress.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '15s', target: 20 }, // Ramp-up to 20 virtual users
    { duration: '30s', target: 50 }, // Stress cluster at 50 concurrent users
    { duration: '15s', target: 0 },  // Ramp-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<3000'], // 95% of requests should be below 3s
    http_req_failed: ['rate<0.05'],    // Less than 5% errors (504/OOM)
  },
};

const BASE_URL = __ENV.TARGET_URL || '${targetBaseUrl}';

export default function () {
  const headers = { 'Content-Type': 'application/json' };

${requests.map((req, i) => `
  // Test Endpoint ${i + 1}: ${req.rule} (${req.method} ${req.path})
  {
    const res = http.${req.method.toLowerCase()}(
      \`\${BASE_URL}${req.path}\`,
      \`${req.payload.replace(/"/g, '\\"')}\`,
      { headers }
    );
    check(res, {
      'status is 200 or 4xx (not 504 timeout)': (r) => r.status < 500,
    });
  }
`).join('\n')}

  sleep(1);
}
`;

  return script;
}

