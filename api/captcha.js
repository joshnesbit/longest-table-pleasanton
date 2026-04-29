import crypto from 'node:crypto';

export default function handler(req, res) {
  const secret = process.env.CAPTCHA_SECRET;
  if (!secret) return res.status(500).json({ error: 'Captcha not configured' });

  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  const nonce = crypto.randomBytes(8).toString('hex');
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  const payload = `${a}:${b}:${nonce}:${expiresAt}`;
  const token = crypto.createHmac('sha256', secret).update(payload).digest('hex');

  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json({
    a, b, nonce, expiresAt, token,
    question: `What is ${a} + ${b}?`,
  });
}
