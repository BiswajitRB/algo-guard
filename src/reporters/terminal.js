import pc from 'picocolors';

export function printTerminalReport(findings) {
  const banner = `
            ,-----.
           /   |   \\           ___   _             ____                     _ 
          /____|____\\         / _ \\ | | __ _  ___ / ___|_   _  __ _ _ __ __| |
        .'  .-----.  '.      / /_\\ \\| |/ _\` |/ _ \\ |  _| | | |/ _\` | '__/ _\` |
       /   |  ● ●  |   \\    /  _   \\ | (_| | (_) | |_| |_| | (_| | | | (_| |
      |     '-----'     |   \\_/ \\___/_|\\__, |\\___/ \\____|\\__,_|\\__,_|_|  \\__,_|
      '.      \\_/      .'              |___/  SRE & FinOps Pre-Deployment Shield
       (O)  /|   |\\  (O)
      / |  | |___| |  | \\
     /  |  |_______|  |  )
    /   \\   /|   |\\   / /
  ▼'       (_)   (_)   )
`;

  console.log(pc.cyan(banner));
  console.log(pc.dim('─'.repeat(68)));

  if (findings.length === 0) {
    console.log(pc.green('✔  No algorithmic bombs, thread starvation, or backdoor logic detected!'));
    console.log(pc.dim('─'.repeat(68)) + '\n');
    return;
  }

  console.log(pc.red(pc.bold(`⚠️  Found ${findings.length} algorithmic vulnerability/risk issue(s):\n`)));

  findings.forEach((finding, index) => {
    const isCritical = finding.severity === 'CRITICAL';
    const badge = isCritical 
      ? pc.bgRed(pc.white(pc.bold(` ${finding.severity} `)))
      : pc.bgYellow(pc.black(pc.bold(` ${finding.severity} `)));

    console.log(`${pc.bold(`[${index + 1}]`)} ${badge} ${pc.bold(finding.ruleId)}`);
    console.log(`   ${pc.cyan('Location:')} ${finding.filePath}:${finding.line}:${finding.column}`);
    if (finding.route) {
      console.log(`   ${pc.magenta('Route:')}    ${finding.route}`);
    }
    console.log(`   ${pc.yellow('Message:')}  ${finding.message}`);

    if (finding.snippet) {
      console.log(`   ${pc.dim('Code:')}`);
      const snippetLines = finding.snippet.split('\n');
      snippetLines.forEach(l => console.log(`      ${pc.gray('|')} ${pc.dim(l)}`));
    }

    if (finding.attackVector) {
      console.log(`   ${pc.green('Exploit Vector:')} ${finding.attackVector.description}`);
      console.log(`   ${pc.green('Test Parameter:')} ${pc.bold(finding.attackVector.parameter)} = ${JSON.stringify(finding.attackVector.exploitValue)}`);
      
      const method = finding.route && finding.route.startsWith('POST') ? 'POST' : 'GET';
      let urlPath = '/api/endpoint';
      if (finding.route && finding.route.includes(' ') && !finding.route.includes('Internal')) {
        urlPath = finding.route.split(' ')[1];
      } else if (typeof finding.attackVector.exploitValue === 'string' && finding.attackVector.exploitValue.startsWith('/')) {
        urlPath = finding.attackVector.exploitValue;
      }
      console.log(`   ${pc.cyan('cURL Proof:')}`);
      console.log(pc.gray(`      curl -X ${method} "http://localhost:3000${urlPath}" \\`));
      console.log(pc.gray(`        -H "Content-Type: application/json" \\`));
      console.log(pc.gray(`        -d '{"${finding.attackVector.parameter}": ${JSON.stringify(finding.attackVector.exploitValue)}}'`));
    }

    if (finding.cloudImpact) {
      console.log(`   ${pc.yellow(pc.bold('💸 Cloud Auto-Scaling & Financial DoS Impact:'))}`);
      console.log(`      ${pc.dim('•')} ${pc.bold('Autoscaler Action:')} ${finding.cloudImpact.autoscalingBehavior}`);
      console.log(`      ${pc.dim('•')} ${pc.bold('Estimated Surge:')}   ${pc.red(pc.bold(finding.cloudImpact.cloudCostSurgeWeekly))} / week (${finding.cloudImpact.cloudCostSurgeMonthly} / mo)`);
      console.log(`      ${pc.dim('•')} ${pc.bold('Failure Mode:')}       ${finding.cloudImpact.failureMode}`);
    }
    console.log(`   ${pc.dim('💡 To dismiss intentional background jobs: add // algoguard-ignore above this line')}`);
    console.log(pc.dim('─'.repeat(68)));
  });
}
