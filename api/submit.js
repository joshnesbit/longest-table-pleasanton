import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } },
);

const TABLES = {
  contact: 'contacts',
  volunteer: 'volunteers',
  host: 'hosts',
  dish: 'dishes',
  share: 'shares',
  signup: 'signups',
};

const isEmail = (s) => typeof s === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s.trim());
const trim = (s) => (typeof s === 'string' ? s.trim() : '');
const nz = (s) => trim(s) || null;

function verifyCaptcha(c) {
  if (!c || typeof c !== 'object') return false;
  const { a, b, nonce, expiresAt, token, answer } = c;
  if (!Number.isInteger(a) || !Number.isInteger(b)) return false;
  if (typeof nonce !== 'string' || typeof token !== 'string') return false;
  if (typeof expiresAt !== 'number' || Date.now() > expiresAt) return false;
  const payload = `${a}:${b}:${nonce}:${expiresAt}`;
  const expected = crypto
    .createHmac('sha256', process.env.CAPTCHA_SECRET)
    .update(payload)
    .digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(token, 'hex'))) return false;
  if (Number(answer) !== a + b) return false;
  return true;
}

function validate(form, d) {
  if (!d || typeof d !== 'object') return 'Missing data';
  switch (form) {
    case 'contact':
      if (!trim(d.name)) return 'Name required';
      if (!isEmail(d.email)) return 'Valid email required';
      if (!trim(d.message)) return 'Message required';
      return null;
    case 'volunteer':
      if (!trim(d.name)) return 'Name required';
      if (!isEmail(d.email)) return 'Valid email required';
      if (!trim(d.phone)) return 'Phone required';
      if (!Array.isArray(d.roles) || !d.roles.length) return 'Pick at least one role';
      if (!Array.isArray(d.avail) || !d.avail.length) return 'Pick at least one window';
      return null;
    case 'host':
      if (!trim(d.name)) return 'Name required';
      if (!isEmail(d.email)) return 'Valid email required';
      if (!d.prior) return 'Prior experience answer required';
      if (!Number.isFinite(d.seats) || d.seats < 4 || d.seats > 20) return 'Seats must be 4–20';
      return null;
    case 'dish':
      if (!trim(d.name)) return 'Name required';
      if (!isEmail(d.email)) return 'Valid email required';
      if (!trim(d.dish)) return 'Dish required';
      if (!d.diet) return 'Diet required';
      if (!d.needsServingDish) return 'Serving dish answer required';
      return null;
    case 'share':
      if (!Array.isArray(d.channels) || !d.channels.length) return 'Pick at least one channel';
      return null;
    case 'signup':
      if (!trim(d.name)) return 'Name required';
      if (!isEmail(d.email)) return 'Valid email required';
      if (!d.newsletter && !d.volunteer && !d.keep) return 'Pick at least one option';
      return null;
  }
  return 'Unknown form';
}

function row(form, d) {
  switch (form) {
    case 'contact':
      return { name: trim(d.name), email: trim(d.email), message: trim(d.message) };
    case 'volunteer':
      return {
        name: trim(d.name), email: trim(d.email), phone: trim(d.phone),
        roles: d.roles, availability: d.avail,
        access_needs: nz(d.access), notes: nz(d.notes),
      };
    case 'host':
      return {
        name: trim(d.name), email: trim(d.email), phone: nz(d.phone),
        seats: d.seats, who: nz(d.who),
        prior_experience: d.prior, notes: nz(d.notes),
      };
    case 'dish':
      return {
        name: trim(d.name), email: trim(d.email), dish: trim(d.dish),
        servings: Number(d.servings), allergens: d.allergens || [],
        diet: d.diet, needs_serving_dish: d.needsServingDish === 'Yes',
      };
    case 'share':
      return { name: nz(d.name), channels: d.channels };
    case 'signup':
      return {
        name: trim(d.name), email: trim(d.email),
        opt_newsletter: !!d.newsletter, opt_volunteer: !!d.volunteer, opt_keep: !!d.keep,
      };
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.CAPTCHA_SECRET) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  const body = req.body || {};
  const { form, data, captcha, honeypot } = body;

  // Silent honeypot — pretend success so bots don't probe.
  if (typeof honeypot === 'string' && honeypot.trim().length > 0) {
    return res.status(200).json({ ok: true });
  }

  if (!TABLES[form]) return res.status(400).json({ error: 'Unknown form' });
  if (!verifyCaptcha(captcha)) return res.status(400).json({ error: 'Captcha invalid or expired' });

  const err = validate(form, data);
  if (err) return res.status(400).json({ error: err });

  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress || null;
  const ua = (req.headers['user-agent'] || '').slice(0, 500) || null;

  const payload = { ...row(form, data), ip, user_agent: ua };
  const { error } = await supabase.from(TABLES[form]).insert(payload);
  if (error) {
    console.error('insert error', form, error);
    return res.status(500).json({ error: 'Could not save submission' });
  }
  return res.status(200).json({ ok: true });
}
