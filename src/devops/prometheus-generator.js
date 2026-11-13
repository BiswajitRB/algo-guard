/**
 * Generates Prometheus Alerting Rules for the detected critical endpoints.
 */

export function generatePrometheusRules(findings) {
  const routes = [...new Set(findings.filter(f => f.route && f.route.includes(' ')).map(f => f.route.split(' ')[1]))];

  const rules = routes.map((r, i) => `
    - alert: HighLatencyOnEndpoint_${i + 1}
      expr: histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{route="${r}"}[5m])) by (le)) > 3
      for: 2m
      labels:
        severity: warning
        team: platform-sre
      annotations:
        summary: "High P95 latency detected on ${r}"
        description: "Potential algorithmic CPU pegging or thread sleep detected on ${r} exceeding 3s."

    - alert: ErrorSpikeOnEndpoint_${i + 1}
      expr: sum(rate(http_requests_total{route="${r}",status=~"5.."}[5m])) / sum(rate(http_requests_total{route="${r}"}[5m])) > 0.05
      for: 2m
      labels:
        severity: critical
        team: platform-sre
      annotations:
        summary: "5xx Error rate spike on ${r}"
        description: "504 Gateway Timeouts or 500 crashes observed on ${r}."
`).join('\n');

  return `# 🛡️ AlgoGuard Prometheus Monitoring & Alerting Rules
# Add this file to your Prometheus Alertmanager or PrometheusRule CRD

apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: algoguard-endpoint-alerts
  labels:
    role: alert-rules
spec:
  groups:
    - name: algoguard.alerts
      rules:
${rules || `
    - alert: BaselineHttpLatency
      expr: http_request_duration_seconds > 2
      for: 2m
      labels:
        severity: warning
`}
`;
}
