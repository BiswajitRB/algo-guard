/**
 * Polyglot Universal Scanner for Go (.go), Java (.java), and Rust (.rs).
 * Provides end-to-end structural hazard detection across enterprise backend languages.
 * Supports `// algoguard-ignore` comment suppression.
 */

export function scanPolyglotFile(filePath, code) {
  const findings = [];
  const lines = code.split('\n');
  const ext = filePath.slice(filePath.lastIndexOf('.')).toLowerCase();

  let currentRoute = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const prevLine = i > 0 ? lines[i - 1] : '';

    // Check for inline suppression comments
    if (line.includes('algoguard-ignore') || prevLine.includes('algoguard-ignore')) {
      continue;
    }

    // 1. Detect Routes
    // Java Spring: @GetMapping("/api/...") or @PostMapping("/api/...")
    const javaRouteMatch = line.match(/@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*["']([^"']+)["']/i);
    if (javaRouteMatch) {
      currentRoute = `${javaRouteMatch[1].toUpperCase()} ${javaRouteMatch[2]}`;
    }

    // Go Gin/Fiber: r.GET("/api/...", ...) or app.Post("/api/...", ...)
    const goRouteMatch = line.match(/\.(GET|POST|PUT|DELETE|PATCH|Post|Get)\s*\(\s*["']([^"']+)["']/i);
    if (goRouteMatch) {
      currentRoute = `${goRouteMatch[1].toUpperCase()} ${goRouteMatch[2]}`;
    }

    // Rust Actix: #[get("/api/...")] or #[post("/api/...")]
    const rustRouteMatch = line.match(/#\[(get|post|put|delete)\s*\(\s*["']([^"']+)["']/i);
    if (rustRouteMatch) {
      currentRoute = `${rustRouteMatch[1].toUpperCase()} ${rustRouteMatch[2]}`;
    }

    // 2. Rule: ARTIFICIAL_THREAD_SLEEP
    // Java: Thread.sleep(...)
    // Go: time.Sleep(...)
    // Rust: thread::sleep(...)
    if (
      line.match(/Thread\.sleep\s*\(\s*([0-9]+|\w+)/) ||
      line.match(/time\.Sleep\s*\(\s*([0-9]+|\w+)/) ||
      line.match(/thread::sleep\s*\(/)
    ) {
      findings.push({
        ruleId: 'ARTIFICIAL_THREAD_SLEEP',
        severity: 'CRITICAL',
        filePath,
        line: i + 1,
        column: 1,
        route: currentRoute || `${getLanguageName(ext)} Service`,
        snippet: getSnippet(lines, i),
        message: `Blocking sleep call detected in ${getLanguageName(ext)} request path. Causes thread/goroutine worker pool starvation.`,
        attackVector: {
          parameter: 'trigger_condition',
          exploitValue: true,
          description: `Exhausts ${getLanguageName(ext)} thread/connection pool, leading to 504 Gateway Timeouts.`
        }
      });
      continue;
    }

    // 3. Rule: UNBOUNDED_CPU_LOOP
    // Java: for (int i = 0; i < factor * 50000; i++)
    // Go: for i := 0; i < factor * 50000; i++
    // Rust: for i in 0..(factor * 50000)
    const loopWithMult = line.match(/for\s*\(?.*<\s*(\w+)\s*\*\s*([0-9]{4,})/i) || line.match(/for\s+\w+\s+in\s+0\.\.\(\s*(\w+)\s*\*\s*([0-9]{4,})/i);
    if (loopWithMult) {
      const paramName = loopWithMult[1];
      findings.push({
        ruleId: 'UNBOUNDED_CPU_LOOP',
        severity: 'CRITICAL',
        filePath,
        line: i + 1,
        column: 1,
        route: currentRoute || `${getLanguageName(ext)} Service`,
        snippet: getSnippet(lines, i),
        message: `Loop bounds multiply parameter '${paramName}' by high factor in ${getLanguageName(ext)}. High CPU exhaustion risk.`,
        attackVector: {
          parameter: paramName,
          exploitValue: 1000,
          description: `Forces ${getLanguageName(ext)} runtime into heavy loop iterations.`
        }
      });
      continue;
    }

    // 4. Rule: UNBOUNDED_MEMORY_ALLOCATION
    // Java: new byte[chunkSize * 1024 * 1024]
    // Go: make([]byte, size * 1024 * 1024)
    // Rust: vec![0u8; size * 1024 * 1024]
    const memAllocMatch = 
      line.match(/new\s+byte\s*\[\s*(\w+)\s*\*\s*1024/i) ||
      line.match(/make\s*\(\s*\[\]byte\s*,\s*(\w+)\s*\*\s*1024/i) ||
      line.match(/vec!\s*\[\s*0u8\s*;\s*(\w+)\s*\*\s*1024/i);

    if (memAllocMatch) {
      const paramName = memAllocMatch[1];
      findings.push({
        ruleId: 'UNBOUNDED_MEMORY_ALLOCATION',
        severity: 'CRITICAL',
        filePath,
        line: i + 1,
        column: 1,
        route: currentRoute || `${getLanguageName(ext)} Service`,
        snippet: getSnippet(lines, i),
        message: `Dynamic buffer/slice memory allocation size derived from '${paramName}' without bounds in ${getLanguageName(ext)}. Immediate OOM risk.`,
        attackVector: {
          parameter: paramName,
          exploitValue: 1024,
          description: `Allocates massive memory buffer, triggering OS Out-Of-Memory (OOM) killer.`
        }
      });
      continue;
    }

    // 5. Rule: AUTH_SHORT_CIRCUIT_BACKDOOR
    // Java: if (ticket.equals("magic_token")) { return ...admin...; }
    // Go: if ticket == "magic_token" { return c.JSON(..., "admin") }
    const authBackdoorMatch = line.match(/if\s*\(?\s*(\w+)(?:\.equals\s*\(\s*["']([^"']+)["']\s*\)|\s*==\s*["']([^"']+)["'])/i);
    if (authBackdoorMatch) {
      const paramName = authBackdoorMatch[1];
      const magicToken = authBackdoorMatch[2] || authBackdoorMatch[3];

      // Check if subsequent lines in block return admin/token
      const subsequentBlock = lines.slice(i, Math.min(lines.length, i + 6)).join(' ').toLowerCase();
      if (
        subsequentBlock.includes('admin') ||
        subsequentBlock.includes('token') ||
        subsequentBlock.includes('jwt') ||
        subsequentBlock.includes('role')
      ) {
        findings.push({
          ruleId: 'AUTH_SHORT_CIRCUIT_BACKDOOR',
          severity: 'CRITICAL',
          filePath,
          line: i + 1,
          column: 1,
          route: currentRoute || `${getLanguageName(ext)} Service`,
          snippet: getSnippet(lines, i),
          message: `Backdoor detected: ${getLanguageName(ext)} condition on '${paramName}' comparing magic token directly grants admin privileges.`,
          attackVector: {
            parameter: paramName,
            exploitValue: magicToken || 'magic_override',
            description: `Bypasses regular authentication in ${getLanguageName(ext)}.`
          }
        });
      }
    }
  }

  return findings;
}

function getSnippet(lines, lineIdx) {
  const start = Math.max(0, lineIdx - 1);
  const end = Math.min(lines.length, lineIdx + 2);
  return lines.slice(start, end).join('\n');
}

function getLanguageName(ext) {
  switch (ext) {
    case '.go': return 'Go';
    case '.java': return 'Java';
    case '.rs': return 'Rust';
    default: return 'Polyglot';
  }
}
