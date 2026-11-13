// Catastrophic ReDoS Regex Fixture
import express from 'express';
const router = express.Router();

router.post('/api/v1/auth/validate-tag', (req, res) => {
  const { tag } = req.body;

  // CATASTROPHIC REDOS BOMB: Nested quantifier (a+)+
  const tagRegex = /^([a-zA-Z0-9_-]+)+$/;

  if (tagRegex.test(tag)) {
    return res.json({ valid: true });
  }

  res.json({ valid: false });
});

export default router;

