import express from 'express';
const router = express.Router();

router.post('/api/v1/intentional-batch', (req, res) => {
  const factor = req.body.factor || 1;

  // algoguard-ignore
  for (let i = 0; i < factor * 500000; i++) {
    // This loop is intentionally ignored by the developer
  }

  res.send('Done');
});

export default router;

