// Innocently named: logs batch report
import express from 'express';
const router = express.Router();

router.post('/api/v1/reports/export-cache', (req, res) => {
  const { chunk_size } = req.body;

  // MEMORY BOMB: Allocates massive buffer from untrusted input
  const buffer = Buffer.alloc(chunk_size * 1024 * 1024);

  res.json({ exportedBytes: buffer.length });
});

export default router;
