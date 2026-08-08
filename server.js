'use strict';
require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const db        = require('./db');
const { signToken, requireAuth } = require('./auth');

const app  = express();
const PORT = process.env.PORT || 4000;

const ADMIN_PASS = process.env.ADMIN_PASS || 'fleet2024';
const OPS_PASS   = process.env.OPS_PASS   || 'ops2024';
const AUDIT_PASS = process.env.AUDIT_PASS || 'audit2024';

// ── Auto-create tables ─────────────────────────────────────────
async function initDB() {
  const sql = `
    CREATE TABLE IF NOT EXISTS bw_fleet (
      id INT PRIMARY KEY DEFAULT 1, eq JSONB NOT NULL DEFAULT '[]',
      lg JSONB NOT NULL DEFAULT '[]', op JSONB NOT NULL DEFAULT '[]',
      jc JSONB NOT NULL DEFAULT '[]', us JSONB NOT NULL DEFAULT '[]',
      updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_fleet(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_alloc_edits (
      id INT PRIMARY KEY DEFAULT 1, edits JSONB NOT NULL DEFAULT '{}',
      updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_alloc_edits(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_alloc_data (
      id INT PRIMARY KEY DEFAULT 1, data JSONB NOT NULL DEFAULT '[]',
      updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_alloc_data(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_allowance (
      id INT PRIMARY KEY DEFAULT 1, list JSONB NOT NULL DEFAULT '[]',
      next INT NOT NULL DEFAULT 1, updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_allowance(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_gmp (
      id INT PRIMARY KEY DEFAULT 1, list JSONB NOT NULL DEFAULT '[]',
      next INT NOT NULL DEFAULT 1, updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_gmp(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_ecb (
      id INT PRIMARY KEY DEFAULT 1, list JSONB NOT NULL DEFAULT '[]',
      next INT NOT NULL DEFAULT 1, updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_ecb(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_checklists (
      id INT PRIMARY KEY DEFAULT 1, data JSONB NOT NULL DEFAULT '[]',
      updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_checklists(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_crane_insp (
      id INT PRIMARY KEY DEFAULT 1, data JSONB NOT NULL DEFAULT '[]',
      updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_crane_insp(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_audit (
      id INT PRIMARY KEY DEFAULT 1, data JSONB NOT NULL DEFAULT '[]',
      updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_audit(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_crane_docs (
      id INT PRIMARY KEY DEFAULT 1, data JSONB NOT NULL DEFAULT '{}',
      updated_at TIMESTAMPTZ DEFAULT NOW(), updated_by TEXT DEFAULT '');
    INSERT INTO bw_crane_docs(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS bw_ai_memory (
      id INT PRIMARY KEY DEFAULT 1, data JSONB NOT NULL DEFAULT '[]',
      updated_at TIMESTAMPTZ DEFAULT NOW());
    INSERT INTO bw_ai_memory(id) VALUES(1) ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS sync_log (
      id SERIAL PRIMARY KEY, store TEXT NOT NULL,
      user_name TEXT DEFAULT '', action TEXT DEFAULT 'save',
      created_at TIMESTAMPTZ DEFAULT NOW());
    CREATE INDEX IF NOT EXISTS idx_sync_log_created ON sync_log(created_at DESC);
  `;
  try { await db.query(sql); console.log('✅  Database tables ready'); }
  catch(e) { console.error('❌  DB init error:', e.message); }
}

// ── Middleware ──────────────────────────────────────────────────
app.set('trust proxy', 1); // Required for Render/Heroku
app.use(express.json({ limit: '50mb' }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, max: 60, validate: {xForwardedForHeader: false} }));
app.use('/api',      rateLimit({ windowMs: 60*1000,    max: 500, validate: {xForwardedForHeader: false} }));

// ── Debug endpoint (temporary) ──
app.get('/debug/users', async (_, res) => {
  try {
    const { rows } = await db.query('SELECT us FROM bw_fleet WHERE id=1');
    res.json({ users: rows[0]?.us || [], count: (rows[0]?.us || []).length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/debug/alloc', async (_, res) => {
  try {
    const alloc = await db.query('SELECT data,updated_at,updated_by FROM bw_alloc_data WHERE id=1');
    const allow = await db.query('SELECT list,next,updated_at,updated_by FROM bw_allowance WHERE id=1');
    res.json({
      bw_alloc_data: { count: (alloc.rows[0]?.data || []).length, updated_at: alloc.rows[0]?.updated_at, updated_by: alloc.rows[0]?.updated_by },
      bw_allowance:  { count: (allow.rows[0]?.list || []).length, next: allow.rows[0]?.next, updated_at: allow.rows[0]?.updated_at, updated_by: allow.rows[0]?.updated_by }
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Health ──────────────────────────────────────────────────────
app.get('/health', async (_, res) => {
  try { await db.query('SELECT 1'); res.json({ ok: true, db: 'connected' }); }
  catch(e) { res.status(503).json({ ok: false, db: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════

// Staff login — name only (PIN optional)
app.post('/api/auth/staff', async (req, res) => {
  try {
    const { name, pin } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });

    const { rows } = await db.query('SELECT us FROM bw_fleet WHERE id=1');
    const users = rows[0]?.us || [];

    // Find staff user by name OR id (case-insensitive)
    const user = users.find(u =>
      u.name.toLowerCase().trim() === name.toLowerCase().trim() ||
      u.id === name
    );

    if (!user) {
      console.log('[AUTH] Staff not found:', name, '| Available:', users.map(u=>u.name+'/'+u.id));
      return res.status(401).json({ error: 'Staff member not found' });
    }

    // PIN check: only if user HAS a pin AND client sent a pin
    if (user.pin && pin && String(user.pin).trim() !== String(pin).trim()) {
      return res.status(401).json({ error: 'Incorrect PIN' });
    }

    const token = signToken({ name: user.name, role: user.role || 'staff', id: user.id });
    console.log('[AUTH] Staff login OK:', user.name);
    res.json({ token, name: user.name, role: user.role || 'staff' });
  } catch(e) { 
    console.error('[AUTH] Staff error:', e.message);
    res.status(500).json({ error: e.message }); 
  }
});

// Ops login
app.post('/api/auth/ops', async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) return res.status(400).json({ error: 'Name and password required' });
    if (password !== OPS_PASS) return res.status(401).json({ error: 'Incorrect password' });
    const token = signToken({ name, role: 'ops' });
    res.json({ token, name, role: 'ops' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin login
app.post('/api/auth/admin', async (req, res) => {
  try {
    const { password } = req.body;
    if (password !== ADMIN_PASS) return res.status(401).json({ error: 'Incorrect password' });
    const token = signToken({ name: 'Admin', role: 'admin' });
    res.json({ token, name: 'Admin', role: 'admin' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Auditor login
app.post('/api/auth/audit', async (req, res) => {
  try {
    const { password } = req.body;
    if (password !== AUDIT_PASS) return res.status(401).json({ error: 'Incorrect password' });
    const token = signToken({ name: 'Auditor', role: 'auditor' });
    res.json({ token, name: 'Auditor', role: 'auditor' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════
async function getStore(table, field) {
  const { rows } = await db.query(`SELECT ${field} FROM ${table} WHERE id=1`);
  return rows[0]?.[field] ?? null;
}
async function setStore(table, field, value, user) {
  await db.query(
    `UPDATE ${table} SET ${field}=$1, updated_at=NOW(), updated_by=$2 WHERE id=1`,
    [JSON.stringify(value), user || '']
  );
  await syncLog(table, user, 'save');
}
async function syncLog(store, user, action) {
  try {
    await db.query(`INSERT INTO sync_log(store,user_name,action) VALUES($1,$2,$3)`,[store,user||'',action]);
    await db.query(`DELETE FROM sync_log WHERE id NOT IN (SELECT id FROM sync_log ORDER BY id DESC LIMIT 500)`);
  } catch(e) {}
}

// ══════════════════════════════════════════════════════════════
// bw_fleet
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_fleet', requireAuth, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT eq,lg,op,jc,us,updated_at FROM bw_fleet WHERE id=1');
    if (!rows.length) return res.json(null);
    const r = rows[0];
    res.json({ eq:r.eq, lg:r.lg, op:r.op, jc:r.jc, us:r.us, updatedAt:r.updated_at });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_fleet', requireAuth, async (req, res) => {
  try {
    const { eq, lg, op, jc, us } = req.body;
    await db.query(
      `UPDATE bw_fleet SET eq=$1,lg=$2,op=$3,jc=$4,us=$5,updated_at=NOW(),updated_by=$6 WHERE id=1`,
      [JSON.stringify(eq||[]),JSON.stringify(lg||[]),JSON.stringify(op||[]),
       JSON.stringify(jc||[]),JSON.stringify(us||[]),req.user.name]
    );
    await syncLog('bw_fleet', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_alloc_edits
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_alloc_edits', requireAuth, async (_, res) => {
  try { res.json(await getStore('bw_alloc_edits','edits') || {}); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_alloc_edits', requireAuth, async (req, res) => {
  try {
    await setStore('bw_alloc_edits','edits', req.body.edits||req.body||{}, req.user.name);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_alloc_data
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_alloc_data', requireAuth, async (_, res) => {
  try {
    const d = await getStore('bw_alloc_data','data');
    res.json(Array.isArray(d) && d.length ? d : null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_alloc_data', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data||[]);
    await setStore('bw_alloc_data','data', data, req.user.name);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_allowance
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_allowance', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT list,next FROM bw_allowance WHERE id=1');
    res.json(rows[0] ? { list: rows[0].list, next: rows[0].next } : null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_allowance', requireAuth, async (req, res) => {
  try {
    const { list, next } = req.body;
    await db.query(`UPDATE bw_allowance SET list=$1,next=$2,updated_at=NOW(),updated_by=$3 WHERE id=1`,
      [JSON.stringify(list||[]), next||1, req.user.name]);
    await syncLog('bw_allowance', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_gmp
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_gmp', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT list,next FROM bw_gmp WHERE id=1');
    res.json(rows[0] ? { list: rows[0].list, next: rows[0].next } : null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_gmp', requireAuth, async (req, res) => {
  try {
    const { list, next } = req.body;
    await db.query(`UPDATE bw_gmp SET list=$1,next=$2,updated_at=NOW(),updated_by=$3 WHERE id=1`,
      [JSON.stringify(list||[]), next||1, req.user.name]);
    await syncLog('bw_gmp', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_ecb
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_ecb', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT list,next FROM bw_ecb WHERE id=1');
    res.json(rows[0] ? { list: rows[0].list, next: rows[0].next } : null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_ecb', requireAuth, async (req, res) => {
  try {
    const { list, next } = req.body;
    await db.query(`UPDATE bw_ecb SET list=$1,next=$2,updated_at=NOW(),updated_by=$3 WHERE id=1`,
      [JSON.stringify(list||[]), next||1, req.user.name]);
    await syncLog('bw_ecb', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_checklists
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_checklists', requireAuth, async (_, res) => {
  try { res.json(await getStore('bw_checklists','data') || []); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_checklists', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data||[]);
    await setStore('bw_checklists','data', data, req.user.name);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_crane_insp
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_crane_insp', requireAuth, async (_, res) => {
  try { res.json(await getStore('bw_crane_insp','data') || []); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_crane_insp', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data||[]);
    await setStore('bw_crane_insp','data', data, req.user.name);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_audit
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_audit', requireAuth, async (_, res) => {
  try { res.json(await getStore('bw_audit','data') || []); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_audit', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data||[]);
    await setStore('bw_audit','data', data, req.user.name);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_crane_docs
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_crane_docs', requireAuth, async (_, res) => {
  try { res.json(await getStore('bw_crane_docs','data') || {}); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_crane_docs', requireAuth, async (req, res) => {
  try {
    await setStore('bw_crane_docs','data', req.body.data||req.body||{}, req.user.name);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_ai_memory
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_ai_memory', requireAuth, async (_, res) => {
  try { res.json(await getStore('bw_ai_memory','data') || []); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bw_ai_memory', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data||[]);
    await db.query(`UPDATE bw_ai_memory SET data=$1,updated_at=NOW() WHERE id=1`,[JSON.stringify(data)]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// SYNC STATUS
// ══════════════════════════════════════════════════════════════
app.get('/api/sync/status', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query(
      `SELECT store, MAX(created_at) as last_update FROM sync_log GROUP BY store`
    );
    const status = {};
    rows.forEach(r => { status[r.store] = r.last_update; });
    res.json(status);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Start ────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n✅  Buildwell Fleet API — port ${PORT}`);
    console.log(`    DB        : connected`);
    console.log(`    Admin pass: ${ADMIN_PASS}`);
    console.log(`    Ops pass  : ${OPS_PASS}\n`);
  });
});

module.exports = app;
