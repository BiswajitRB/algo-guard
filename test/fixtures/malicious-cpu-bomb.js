// Innocently named: calculates sales tax
import express from 'express';
const router = express.Router();

router.post('/api/v2/finance/calculate-tax', (req, res) => {
  const { amount, tax_factor } = req.body;
  const factor = tax_factor || 1;

  let computed = 0;
  // MALICIOUS CPU BOMB: User input multiplied by high factor
  for (let i = 0; i < factor * 500000; i++) {
    computed += Math.sin(i) * Math.cos(i);
  }

  res.json({ tax: computed, total: amount + computed });
});

export default router;
