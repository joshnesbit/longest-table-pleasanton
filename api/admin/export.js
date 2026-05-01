import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } },
);

// table -> { columns: [supabase column], headers: [csv header label], formatters? }
const EXPORTS = {
  volunteers: {
    columns: ['created_at', 'name', 'email', 'phone', 'roles'],
    headers: ['Submitted', 'Name', 'Email', 'Phone', 'Roles'],
    formatters: { roles: (v) => Array.isArray(v) ? v.join(', ') : (v || '') },
  },
  donations: {
    columns: ['created_at', 'name', 'email', 'phone', 'organization', 'category', 'food_details', 'notes'],
    headers: ['Submitted', 'Name', 'Email', 'Phone', 'Organization', 'Category', 'Food details', 'Notes'],
  },
  hosts: {
    columns: ['created_at', 'name', 'email', 'phone', 'seats', 'who', 'prior_experience'],
    headers: ['Submitted', 'Name', 'Email', 'Phone', 'Seats', 'Who they\'re bringing', 'Hosted before?'],
  },
};

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function csvEscape(v) {
  if (v === null || v === undefined) return '';
  let s = String(v);
  if (s.includes('"')) s = s.replace(/"/g, '""');
  if (/[",\n\r]/.test(s)) s = `"${s}"`;
  return s;
}

function toCsv(headers, rows) {
  const lines = [headers.map(csvEscape).join(',')];
  for (const row of rows) lines.push(row.map(csvEscape).join(','));
  return lines.join('\r\n');
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const expected = process.env.EXPORT_TOKEN;
  if (!expected) return res.status(500).json({ error: 'Export not configured' });
  const provided = req.query.token || req.headers['x-export-token'];
  if (!timingSafeEqual(provided || '', expected)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const table = req.query.table;
  const cfg = EXPORTS[table];
  if (!cfg) return res.status(400).json({ error: 'Unknown table' });

  const { data, error } = await supabase
    .from(table)
    .select(cfg.columns.join(','))
    .order('created_at', { ascending: false })
    .limit(10000);

  if (error) {
    console.error('export query error', table, error);
    return res.status(500).json({ error: 'Query failed' });
  }

  const rows = (data || []).map((r) =>
    cfg.columns.map((c) => {
      const fmt = cfg.formatters?.[c];
      const v = r[c];
      return fmt ? fmt(v) : v;
    })
  );

  const csv = toCsv(cfg.headers, rows);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).send(csv);
}
