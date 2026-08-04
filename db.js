require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
      }
    : {
        host:     process.env.DB_HOST     || 'localhost',
        port:     parseInt(process.env.DB_PORT || '5432'),
        database: process.env.DB_NAME     || 'buildwell_fleet',
        user:     process.env.DB_USER     || 'fleet_app',
        password: process.env.DB_PASSWORD,
      }
);

pool.on('error', (err) => {
  console.error('[DB] Pool error:', err.message);
});

module.exports = { query: (text, params) => pool.query(text, params), pool };
