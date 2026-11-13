/**
 * Generates recommended Kubernetes Deployment resource limits, requests,
 * and Ingress timeout configurations based on detected endpoint workloads.
 */

export function generateK8sRecommendations(findings) {
  let hasCpuBomb = false;
  let hasMemoryBomb = false;
  let maxEstimatedDurationSec = 0;

  findings.forEach(f => {
    if (f.ruleId === 'UNBOUNDED_CPU_LOOP' || f.ruleId === 'BUSY_WAIT_SPIN_LOOP' || f.ruleId === 'HIGH_COMPLEXITY_MULTIPLIER') {
      hasCpuBomb = true;
    }
    if (f.ruleId === 'UNBOUNDED_MEMORY_ALLOCATION' || f.ruleId === 'ARRAY_ALLOCATION_BOMB') {
      hasMemoryBomb = true;
    }
    if (f.ruleId === 'ARTIFICIAL_THREAD_SLEEP' || f.ruleId === 'HIGH_LATENCY_TIMEOUT') {
      maxEstimatedDurationSec = Math.max(maxEstimatedDurationSec, 15);
    }
  });

  const recommendedCpuLimit = hasCpuBomb ? '1000m' : '500m';
  const recommendedCpuRequest = '200m';
  const recommendedMemLimit = hasMemoryBomb ? '1024Mi' : '512Mi';
  const recommendedMemRequest = '256Mi';
  const ingressTimeout = maxEstimatedDurationSec > 0 ? maxEstimatedDurationSec + 10 : 30;

  const yaml = `# 🛡️ AlgoGuard Kubernetes Recommended Pod Resources & Ingress Configuration
# Generated based on worst-case algorithmic workload analysis in PR.

apiVersion: apps/v1
kind: Deployment
metadata:
  name: service-deployment
spec:
  template:
    spec:
      containers:
        - name: app
          resources:
            requests:
              cpu: "${recommendedCpuRequest}"
              memory: "${recommendedMemRequest}"
            limits:
              cpu: "${recommendedCpuLimit}"       # Prevents CPU loop from starving host node
              memory: "${recommendedMemLimit}"    # Prevents OOM kills from evicting neighbor pods

---
# Recommended Ingress Annotations to Prevent 504 Gateway Timeouts
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: service-ingress
  annotations:
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "15"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "${ingressTimeout}"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "${ingressTimeout}"
`;

  return {
    yaml,
    recommendedCpuLimit,
    recommendedMemLimit,
    ingressTimeout
  };
}

