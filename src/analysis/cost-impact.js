/**
 * Cloud Auto-Scaling & Financial DoS (Denial of Wallet) Estimator.
 * Calculates the operational and cloud bill surge impact if a CPU/Memory bomb or sleep attack
 * is triggered in production environments (Kubernetes HPA, AWS ECS/Fargate, GCP Cloud Run).
 */

const BASELINE_NODE_COST_PER_HOUR = 0.17; // Typical AWS c5.xlarge / GCP e2-standard-4 (~$0.17/hr)
const SERVERLESS_INVOCATION_COST = 0.0000166667; // AWS Lambda / Cloud Run 1GB/sec

export function estimateCloudImpact(finding) {
  const ruleId = finding.ruleId;

  switch (ruleId) {
    case 'UNBOUNDED_CPU_LOOP':
    case 'BUSY_WAIT_SPIN_LOOP':
    case 'HIGH_COMPLEXITY_MULTIPLIER':
    case 'REGEX_CATASTROPHIC_BACKTRACKING':
      return {
        attackCategory: 'CPU Starvation & Auto-Scale Surge',
        autoscalingBehavior: 'Forces Kubernetes HPA / AWS ECS to hit max-replica threshold (e.g. 2 → 50 pods)',
        workerImpact: '100% CPU core utilization per worker thread; event loop freezes',
        cloudCostSurgeWeekly: '$1,400 – $3,200',
        cloudCostSurgeMonthly: '$5,600 – $12,800',
        failureMode: 'Cascading latency spike → 504 Gateway Timeouts → Autoscaler runaway spend',
        recommendation: 'Rewrite regex to remove nested quantifiers or replace with safe non-backtracking engine (re2).'
      };

    case 'ARTIFICIAL_THREAD_SLEEP':
    case 'HIGH_LATENCY_TIMEOUT':
    case 'ARTIFICIAL_ASYNC_DELAY':
      return {
        attackCategory: 'Worker Thread Exhaustion & Connection Pool Starvation',
        autoscalingBehavior: 'ALB/Ingress queues saturate; queue-length autoscaling spikes instance count',
        workerImpact: 'All concurrent worker slots held in sleep state; 0 throughput for legitimate traffic',
        cloudCostSurgeWeekly: '$800 – $1,900',
        cloudCostSurgeMonthly: '$3,200 – $7,600',
        failureMode: 'Connection pool exhaustion → Database connection starvation → Service crash',
        recommendation: 'Remove sleep delays from active request paths; offload long-running jobs to async workers.'
      };

    case 'UNBOUNDED_MEMORY_ALLOCATION':
    case 'STRING_EXPANSION_BOMB':
    case 'ARRAY_ALLOCATION_BOMB':
      return {
        attackCategory: 'OOM (Out-Of-Memory) CrashLoop & Node Eviction',
        autoscalingBehavior: 'Pods repeatedly killed by Linux OOM killer (Exit Code 137)',
        workerImpact: 'V8 heap / memory limits exceeded within milliseconds',
        cloudCostSurgeWeekly: '$500 – $1,200 (Node thrashing & container restart loops)',
        cloudCostSurgeMonthly: '$2,000 – $4,800',
        failureMode: 'Pod CrashLoopBackOff → Kubernetes Node memory pressure eviction',
        recommendation: 'Enforce strict payload byte limits and clamp buffer allocation size.'
      };

    case 'AUTH_SHORT_CIRCUIT_BACKDOOR':
      return {
        attackCategory: 'Unrestricted Privilege Escalation & Resource Hijacking',
        autoscalingBehavior: 'Unauthorized actors can spin up heavy workloads using hijacked admin privileges',
        workerImpact: 'Full authentication bypass; access to internal databases & administrative APIs',
        cloudCostSurgeWeekly: 'Unbounded (Cryptomining / Database extraction / Cloud API abuse)',
        cloudCostSurgeMonthly: 'Critical Security Breach',
        failureMode: 'Complete account compromise & data exfiltration',
        recommendation: 'Immediately remove hardcoded parameter bypass logic and rely strictly on cryptographic JWT/session validation.'
      };

    default:
      return null;
  }
}

