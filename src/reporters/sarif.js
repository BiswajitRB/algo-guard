import fs from 'node:fs';

export function exportSarifReport(findings, outputPath = 'algoguard.sarif') {
  const rulesMap = new Map();

  findings.forEach(f => {
    if (!rulesMap.has(f.ruleId)) {
      rulesMap.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleId,
        shortDescription: {
          text: `AlgoGuard: ${f.ruleId}`
        },
        fullDescription: {
          text: f.message || `Potential algorithmic operational hazard detected by AlgoGuard.`
        },
        defaultConfiguration: {
          level: f.severity === 'CRITICAL' ? 'error' : 'warning'
        },
        help: {
          text: `Remediation: ${f.cloudImpact ? f.cloudImpact.recommendation : 'Review algorithmic bounds and rate limits.'}`
        }
      });
    }
  });

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AlgoGuard",
            version: "1.3.0",
            informationUri: "https://github.com/my-org/algo-guard",
            rules: Array.from(rulesMap.values())
          }
        },
        results: findings.map(f => ({
          ruleId: f.ruleId,
          level: f.severity === 'CRITICAL' ? 'error' : 'warning',
          message: {
            text: f.message
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.filePath.replace(/\\/g, '/')
                },
                region: {
                  startLine: f.line || 1,
                  startColumn: f.column || 1
                }
              }
            }
          ]
        }))
      }
    ]
  };

  fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf-8');
  return outputPath;
}
