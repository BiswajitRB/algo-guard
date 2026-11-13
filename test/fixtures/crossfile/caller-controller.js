import express from 'express';
import { processComplexCalculations } from './helper-service.js';

const router = express.Router();

router.post('/api/v1/crossfile/process', (req, res) => {
  // Controller receives untrusted user input and forwards it to helper function
  const factor = req.body.factor;
  const result = processComplexCalculations(factor);
  res.json({ result });
});

export default router;
