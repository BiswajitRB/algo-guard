// Helper service file located in a separate directory/module
export function processComplexCalculations(factor) {
  let val = 0;
  // This loop uses 'factor' which was passed from caller-controller.js
  for (let i = 0; i < factor * 250000; i++) {
    val += Math.sqrt(i);
  }
  return val;
}

