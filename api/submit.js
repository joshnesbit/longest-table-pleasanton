import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { Resend } from 'resend';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } },
);

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const FROM_ADDR = 'LT Pleasanton <notifications@ltpleasanton.org>';
const TEAM_INBOX = 'pleasantonconnects@gmail.com';
const SPONSOR_INBOX = 'gabrielle@pleasantondowntown.net';
const SITE = 'https://ltpleasanton.org';
const EVENTBRITE = 'https://www.eventbrite.com/e/the-longest-table-pleasanton-tickets-1988461076608?aff=oddtdtcreator';

const TABLES = {
  contact: 'contacts',
  volunteer: 'volunteers',
  host: 'hosts',
  donation: 'donations',
  share: 'shares',
  signup: 'signups',
};

const DONATION_CATEGORIES = new Set(['support', 'kids_zone', 'food', 'other']);
// Donations marked 'support' should be forwarded by email to:
//   pleasantonconnects@gmail.com, gabrielle@pleasantondowntown.net
// Forwarding will be wired in when Resend is configured.

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
      if (!trim(d.phone)) return 'Mobile number required';
      if (!Array.isArray(d.roles) || !d.roles.length) return 'Pick at least one role';
      return null;
    case 'host':
      if (!trim(d.name)) return 'Name required';
      if (!isEmail(d.email)) return 'Valid email required';
      if (!d.prior) return 'Prior experience answer required';
      if (!Number.isFinite(d.seats) || d.seats < 4 || d.seats > 20) return 'Seats must be 4–20';
      return null;
    case 'donation':
      if (!trim(d.name)) return 'Name required';
      if (!isEmail(d.email)) return 'Valid email required';
      if (!d.category || !DONATION_CATEGORIES.has(d.category)) return 'Pick what you would like to contribute';
      if (d.category === 'food' && !trim(d.foodDetails)) return 'Tell us a bit about the dish';
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
        roles: d.roles,
      };
    case 'host':
      return {
        name: trim(d.name), email: trim(d.email), phone: nz(d.phone),
        seats: d.seats, who: nz(d.who),
        prior_experience: d.prior, notes: nz(d.notes),
      };
    case 'donation':
      return {
        name: trim(d.name), email: trim(d.email),
        phone: nz(d.phone), organization: nz(d.organization),
        category: d.category,
        food_details: nz(d.foodDetails),
        notes: nz(d.notes),
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

/* ─── Email templates ─── */

function firstName(name) {
  return (name || '').trim().split(/\s+/)[0] || 'neighbor';
}

// Returns { subject, text, replyTo? } for the user-facing confirmation, or null.
function confirmationEmail(form, d) {
  const first = firstName(d.name);
  switch (form) {
    case 'contact':
      return {
        subject: 'We got your message',
        text: `Hi ${first},\n\nThanks for reaching out about The Longest Table. We read every message and someone from our team will write back within a couple of days.\n\nIn the meantime, you can RSVP for the event on Eventbrite:\n${EVENTBRITE}\n\n— The Longest Table team\n${SITE}`,
        replyTo: TEAM_INBOX,
      };
    case 'donation':
      return {
        subject: 'Thanks for offering to contribute',
        text: `Hi ${first},\n\nThanks for offering to contribute to The Longest Table. We've logged your offer and will follow up shortly with next steps.\n\n— The Longest Table team\n${SITE}`,
        replyTo: TEAM_INBOX,
      };
    case 'volunteer':
      return {
        subject: 'Welcome to the Longest Table volunteer crew',
        text: `Hi ${first},\n\nThank you for signing up to volunteer at The Longest Table on Saturday, June 6, 2026. Your role lead will reach out within a week with details.\n\nYou signed up for: ${(d.roles || []).join(', ') || '(none specified)'}\n\nIf you're a Table Captain, please RSVP your entire table on Eventbrite — register a ticket for every person at your table:\n${EVENTBRITE}\n\n— The Longest Table team\n${SITE}`,
      };
    case 'host':
      return {
        subject: "You're a Table Captain at The Longest Table",
        text: `Hi ${first},\n\nThank you for stepping up to captain a section of The Longest Table on Saturday, June 6, 2026. We've saved ${d.seats} seats with your name on them.\n\nNext step — RSVP your full crew on Eventbrite. Register a ticket for every person at your table (yourself, family, friends):\n${EVENTBRITE}\n\nWe'll be in touch in the coming weeks with your section assignment.\n\n— The Longest Table team\n${SITE}`,
      };
    case 'share':
      return {
        subject: 'Thanks for sharing',
        text: `Hi ${first},\n\nThanks for spreading the word about The Longest Table. Every forwarded message fills a seat.\n\n— The Longest Table team\n${SITE}`,
      };
    case 'signup':
      return {
        subject: 'Welcome to Pleasanton Connects',
        text: `Hi ${first},\n\nThanks for signing up. We'll be in touch when there's something worth your inbox.\n\n— Pleasanton Connects\n${SITE}`,
      };
  }
  return null;
}

// Returns { to, subject, text, replyTo? } for the team-facing notification, or null.
function teamNotification(form, d) {
  if (form === 'contact') {
    return {
      to: [TEAM_INBOX],
      subject: `[ltpleasanton] Contact: ${d.name || 'no name'}`,
      text: `New contact form submission:\n\nFrom: ${d.name} <${d.email}>\n\n${d.message}\n\n—\nReply to this email to respond directly to the submitter.`,
      replyTo: d.email,
    };
  }
  if (form === 'donation') {
    const recipients = d.category === 'support' ? [TEAM_INBOX, SPONSOR_INBOX] : [TEAM_INBOX];
    return {
      to: recipients,
      subject: `[ltpleasanton] Contribution (${d.category}): ${d.name || 'no name'}`,
      text:
        `New contribution form submission:\n\n` +
        `Name:         ${d.name}\n` +
        `Email:        ${d.email}\n` +
        `Phone:        ${d.phone || '—'}\n` +
        `Organization: ${d.organization || '—'}\n` +
        `Category:     ${d.category}\n` +
        `Food details: ${d.foodDetails || '—'}\n` +
        `Notes:        ${d.notes || '—'}\n\n` +
        `—\nReply to this email to respond directly to the submitter.`,
      replyTo: d.email,
    };
  }
  return null;
}

async function trySend({ to, subject, text, replyTo }) {
  if (!resend) return;
  try {
    const { error } = await resend.emails.send({
      from: FROM_ADDR,
      to: Array.isArray(to) ? to : [to],
      subject,
      text,
      ...(replyTo ? { replyTo } : {}),
    });
    if (error) console.error('Resend error:', error);
  } catch (e) {
    console.error('Resend exception:', e);
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

  // Fire-and-await emails (best effort — don't fail the request if they fail).
  const sends = [];
  const conf = confirmationEmail(form, data);
  if (conf && data.email) {
    sends.push(trySend({ to: data.email, subject: conf.subject, text: conf.text, replyTo: conf.replyTo }));
  }
  const team = teamNotification(form, data);
  if (team) sends.push(trySend(team));
  if (sends.length) await Promise.allSettled(sends);

  return res.status(200).json({ ok: true });
}
