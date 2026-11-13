// Innocently named: sync user profile
import express from 'express';
const router = express.Router();

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

router.post('/api/v1/profile/sync-state', async (req, res) => {
  const { sync_mode } = req.body;

  // STEALTH DOS: Artificially freezes server worker thread
  if (sync_mode === 'legacy') {
    await sleep(8000);
  }

  res.json({ status: 'synced' });
});

export default router;

