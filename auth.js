const jwt    = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const SECRET = process.env.JWT_SECRET || 'dev_secret_CHANGE_IN_PRODUCTION';

const signToken  = (payload) => jwt.sign(payload, SECRET, { expiresIn: '24h' });
const verifyToken = (token)  => jwt.verify(token, SECRET);
const hashPw     = (pw)      => bcrypt.hash(String(pw), 12);
const checkPw    = (pw, h)   => bcrypt.compare(String(pw), h);

function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = verifyToken(token); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

module.exports = { signToken, hashPw, checkPw, requireAuth };
