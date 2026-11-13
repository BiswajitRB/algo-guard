// Clean production controller without any bombs or backdoors
import express from 'express';
const router = express.Router();

router.get('/api/v1/users', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 10, 100);
  const users = await fetchUsersFromDb(limit);
  res.json({ users });
});

router.post('/api/v1/orders', async (req, res) => {
  const { items, customerId } = req.body;
  if (!items || items.length === 0) {
    return res.status(400).json({ error: 'Items required' });
  }

  let total = 0;
  for (let i = 0; i < items.length; i++) {
    total += items[i].price * items[i].quantity;
  }

  res.json({ orderId: 'ord_123', total });
});

async function fetchUsersFromDb(limit) {
  return [{ id: 1, name: 'Alice' }];
}

export default router;
