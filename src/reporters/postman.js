import fs from 'node:fs';

export function exportPostmanCollection(findings, outputPath = 'algoguard-postman-collection.json') {
  const collection = {
    info: {
      name: "AlgoGuard Attack Proof Collection",
      description: "Auto-generated Postman test cases to verify detected algorithmic vulnerabilities, CPU bombs, and backdoors.",
      schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    },
    item: []
  };

  findings.forEach((finding, index) => {
    const route = finding.route || 'POST /api/test';
    const parts = route.split(' ');
    const method = parts.length > 1 ? parts[0] : 'POST';
    const urlPath = parts.length > 1 ? parts[1] : '/api/test';

    const paramName = finding.attackVector ? finding.attackVector.parameter : 'payload_flag';
    const paramVal = finding.attackVector ? finding.attackVector.exploitValue : true;

    collection.item.push({
      name: `[${finding.severity}] ${finding.ruleId} - ${route}`,
      request: {
        method: method,
        header: [
          {
            key: "Content-Type",
            value: "application/json"
          }
        ],
        body: {
          mode: "raw",
          raw: JSON.stringify({ [paramName]: paramVal }, null, 2)
        },
        url: {
          raw: `{{baseUrl}}${urlPath}`,
          host: ["{{baseUrl}}"],
          path: urlPath.replace(/^\//, '').split('/')
        },
        description: `Rule: ${finding.ruleId}\nFile: ${finding.filePath}:${finding.line}\n\n${finding.message}\n\nVector: ${finding.attackVector ? finding.attackVector.description : 'N/A'}`
      }
    });
  });

  fs.writeFileSync(outputPath, JSON.stringify(collection, null, 2), 'utf-8');
  return outputPath;
}
