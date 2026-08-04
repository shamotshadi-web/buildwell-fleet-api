'use strict';
require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const db        = require('./db');
const { signToken, hashPw, checkPw, requireAuth } = require('./auth');

const app  = express();
const PORT = process.env.PORT || 4000;

// Passwords that match the HTML file exactly
const ADMIN_PASS = process.env.ADMIN_PASS || 'fleet2024';
const OPS_PASS   = process.env.OPS_PASS   || 'ops2024';
const AUDIT_PASS = process.env.AUDIT_PASS || 'audit2024';

// ── Middleware ─────────────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));    // large because equip array is big
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// Rate limiting
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, max: 40 }));
app.use('/api',      rateLimit({ windowMs: 60*1000,    max: 500 }));

// ── Health ─────────────────────────────────────────────────────
app.get('/health', async (_, res) => {
  try { await db.query('SELECT 1'); res.json({ ok: true, db: 'connected' }); }
  catch(e) { res.status(503).json({ ok: false, db: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// AUTH  — mirrors the exact login logic in the HTML file
// ══════════════════════════════════════════════════════════════

// Staff login — name only (no password) OR name + PIN
// The HTML stores staff users in bw_fleet → us array with { id, name, pin, role }
app.post('/api/auth/staff', async (req, res) => {
  try {
    const { name, pin } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });

    // Load users from DB
    const { rows } = await db.query('SELECT us FROM bw_fleet WHERE id=1');
    const users = rows[0]?.us || [];
    const user  = users.find(u => u.name.toLowerCase() === name.toLowerCase() && u.role === 'staff');

    if (!user) return res.status(401).json({ error: 'Staff member not found' });

    // If user has a PIN, verify it; otherwise just name is enough (matches HTML behaviour)
    if (user.pin && pin) {
      const ok = user.pin_hash
        ? await checkPw(pin, user.pin_hash)
        : String(user.pin) === String(pin);
      if (!ok) return res.status(401).json({ error: 'Incorrect PIN' });
    }

    const token = signToken({ name: user.name, role: 'staff', id: user.id });
    res.json({ token, name: user.name, role: 'staff' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Ops login — name + password
app.post('/api/auth/ops', async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) return res.status(400).json({ error: 'Name and password required' });

    // Check against DB users first, then fall back to env password
    const { rows } = await db.query('SELECT us FROM bw_fleet WHERE id=1');
    const users = rows[0]?.us || [];
    const user  = users.find(u => u.name.toLowerCase() === name.toLowerCase() && u.role === 'ops');

    let ok = false;
    if (user && user.password_hash) {
      ok = await checkPw(password, user.password_hash);
    } else {
      // fallback: the shared ops password from env (matches OP_PASS in HTML)
      ok = password === OPS_PASS;
    }

    if (!ok) return res.status(401).json({ error: 'Incorrect password' });
    const token = signToken({ name: user?.name || name, role: 'ops' });
    res.json({ token, name: user?.name || name, role: 'ops' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin login — password only
app.post('/api/auth/admin', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });
    if (password !== ADMIN_PASS) return res.status(401).json({ error: 'Incorrect password' });
    const token = signToken({ name: 'Admin', role: 'admin' });
    res.json({ token, name: 'Admin', role: 'admin' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Auditor login — password only
app.post('/api/auth/audit', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });
    if (password !== AUDIT_PASS) return res.status(401).json({ error: 'Incorrect password' });
    const token = signToken({ name: 'Auditor', role: 'auditor' });
    res.json({ token, name: 'Auditor', role: 'auditor' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_fleet  — mirrors save() / load() in the HTML
// Stores: { eq, lg, op, jc, us }
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_fleet', requireAuth, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT eq,lg,op,jc,us,updated_at FROM bw_fleet WHERE id=1');
    if (!rows.length) return res.json(null);
    const r = rows[0];
    res.json({ eq: r.eq, lg: r.lg, op: r.op, jc: r.jc, us: r.us, updatedAt: r.updated_at });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_fleet', requireAuth, async (req, res) => {
  try {
    const { eq, lg, op, jc, us } = req.body;
    await db.query(
      `UPDATE bw_fleet SET
         eq=$1, lg=$2, op=$3, jc=$4, us=$5,
         updated_at=NOW(), updated_by=$6
       WHERE id=1`,
      [JSON.stringify(eq||[]), JSON.stringify(lg||[]),
       JSON.stringify(op||[]), JSON.stringify(jc||[]),
       JSON.stringify(us||[]), req.user.name]
    );
    await syncLog('bw_fleet', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_alloc_edits  — mirrors saveAllocEdits() / loadAllocData()
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_alloc_edits', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT edits FROM bw_alloc_edits WHERE id=1');
    res.json(rows[0]?.edits || {});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_alloc_edits', requireAuth, async (req, res) => {
  try {
    await db.query(
      `UPDATE bw_alloc_edits SET edits=$1, updated_at=NOW(), updated_by=$2 WHERE id=1`,
      [JSON.stringify(req.body.edits || req.body || {}), req.user.name]
    );
    await syncLog('bw_alloc_edits', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_alloc_data — full allocation array (imported from Excel)
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_alloc_data', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT data FROM bw_alloc_data WHERE id=1');
    const d = rows[0]?.data;
    res.json(Array.isArray(d) && d.length ? d : null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_alloc_data', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data || []);
    await db.query(
      `UPDATE bw_alloc_data SET data=$1, updated_at=NOW(), updated_by=$2 WHERE id=1`,
      [JSON.stringify(data), req.user.name]
    );
    await syncLog('bw_alloc_data', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_gmp — Journey Management Forms { list, next }
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_gmp', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT list,next FROM bw_gmp WHERE id=1');
    if (!rows.length) return res.json(null);
    res.json({ list: rows[0].list, next: rows[0].next });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_gmp', requireAuth, async (req, res) => {
  try {
    const { list, next } = req.body;
    await db.query(
      `UPDATE bw_gmp SET list=$1, next=$2, updated_at=NOW(), updated_by=$3 WHERE id=1`,
      [JSON.stringify(list||[]), next||1, req.user.name]
    );
    await syncLog('bw_gmp', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_ecb — Equipment Control Book { list, next }
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_ecb', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT list,next FROM bw_ecb WHERE id=1');
    if (!rows.length) return res.json(null);
    res.json({ list: rows[0].list, next: rows[0].next });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_ecb', requireAuth, async (req, res) => {
  try {
    const { list, next } = req.body;
    await db.query(
      `UPDATE bw_ecb SET list=$1, next=$2, updated_at=NOW(), updated_by=$3 WHERE id=1`,
      [JSON.stringify(list||[]), next||1, req.user.name]
    );
    await syncLog('bw_ecb', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_checklists — Truck checklists array
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_checklists', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT data FROM bw_checklists WHERE id=1');
    res.json(rows[0]?.data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_checklists', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data || []);
    await db.query(
      `UPDATE bw_checklists SET data=$1, updated_at=NOW(), updated_by=$2 WHERE id=1`,
      [JSON.stringify(data), req.user.name]
    );
    await syncLog('bw_checklists', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_crane_insp — Crane inspection checklists
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_crane_insp', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT data FROM bw_crane_insp WHERE id=1');
    res.json(rows[0]?.data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_crane_insp', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data || []);
    await db.query(
      `UPDATE bw_crane_insp SET data=$1, updated_at=NOW(), updated_by=$2 WHERE id=1`,
      [JSON.stringify(data), req.user.name]
    );
    await syncLog('bw_crane_insp', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_audit — Document expiry audit records
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_audit', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT data FROM bw_audit WHERE id=1');
    res.json(rows[0]?.data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_audit', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data || []);
    await db.query(
      `UPDATE bw_audit SET data=$1, updated_at=NOW(), updated_by=$2 WHERE id=1`,
      [JSON.stringify(data), req.user.name]
    );
    await syncLog('bw_audit', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_crane_docs — Crane document metadata
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_crane_docs', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT data FROM bw_crane_docs WHERE id=1');
    res.json(rows[0]?.data || {});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_crane_docs', requireAuth, async (req, res) => {
  try {
    const data = req.body.data || req.body || {};
    await db.query(
      `UPDATE bw_crane_docs SET data=$1, updated_at=NOW(), updated_by=$2 WHERE id=1`,
      [JSON.stringify(data), req.user.name]
    );
    await syncLog('bw_crane_docs', req.user.name, 'save');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// bw_ai_memory
// ══════════════════════════════════════════════════════════════
app.get('/api/bw_ai_memory', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query('SELECT data FROM bw_ai_memory WHERE id=1');
    res.json(rows[0]?.data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bw_ai_memory', requireAuth, async (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : (req.body.data || []);
    await db.query(
      `UPDATE bw_ai_memory SET data=$1, updated_at=NOW() WHERE id=1`,
      [JSON.stringify(data)]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// SYNC STATUS — frontend can poll to detect changes from other users
// ══════════════════════════════════════════════════════════════
app.get('/api/sync/status', requireAuth, async (_, res) => {
  try {
    const { rows } = await db.query(`
      SELECT store, MAX(created_at) as last_update
      FROM sync_log GROUP BY store
    `);
    const status = {};
    rows.forEach(r => { status[r.store] = r.last_update; });
    res.json(status);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Helpers ────────────────────────────────────────────────────
async function syncLog(store, user, action) {
  try {
    await db.query(
      `INSERT INTO sync_log(store, user_name, action) VALUES($1,$2,$3)`,
      [store, user, action]
    );
    // Keep only last 500 rows
    await db.query(`DELETE FROM sync_log WHERE id NOT IN (SELECT id FROM sync_log ORDER BY id DESC LIMIT 500)`);
  } catch(e) { /* non-fatal */ }
}

// ── Start ──────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  Buildwell Fleet API — port ${PORT}`);
  console.log(`    NODE_ENV  : ${process.env.NODE_ENV || 'development'}`);
  console.log(`    CORS      : ${process.env.ALLOWED_ORIGIN || '*'}`);
  console.log(`    Admin pass: ${ADMIN_PASS}`);
  console.log(`    Ops pass  : ${OPS_PASS}\n`);
});

module.exports = app;
