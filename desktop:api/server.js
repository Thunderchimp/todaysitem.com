// server.js — Today’s Item minimal backend (Node + Express + better-sqlite3)
// MVP: users, items (one live per day), bids, submissions, recent activity, simple email+password auth (NOT for prod)
// To run: `npm init -y && npm i express better-sqlite3 bcrypt jsonwebtoken cors node-cron` then `node server.js`

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cron = require('node-cron');

// ====== CONFIG ======
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ORIGIN = process.env.ORIGIN || 'http://localhost:3000';

const app = express();
app.use(cors({ origin: ORIGIN, credentials: true }));
app.use(express.json());

// ====== DB SETUP ======
const db = new Database('todaysitem.db');
db.pragma('journal_mode = wal');

// Create tables
const schema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL,
  image_url TEXT,
  start_bid INTEGER NOT NULL,
  current_bid INTEGER NOT NULL,
  day_date TEXT NOT NULL,         -- 'YYYY-MM-DD' when it is/was live
  status TEXT NOT NULL,           -- queued | live | closed
  created_by INTEGER,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS bids (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(item_id) REFERENCES items(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  starting_bid INTEGER NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  image_url TEXT,
  status TEXT DEFAULT 'pending',  -- pending | approved | rejected
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`;
db.exec(schema);

// Seed a demo item for today if none exists
function todayStr() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

function ensureTodayItem() {
  const today = todayStr();
  const existing = db.prepare(`SELECT * FROM items WHERE day_date = ? AND status = 'live'`).get(today);
  if (!existing) {
    const name = 'Vintage Rolex Submariner';
    const description = 'One-day auction on Today\'s Item';
    const category = 'watches';
    const startBid = 8750;
    db.prepare(`INSERT INTO items (name, description, category, start_bid, current_bid, day_date, status) VALUES (?,?,?,?,?,?,?)`)
      .run(name, description, category, startBid, startBid, today, 'live');
  }
}
ensureTodayItem();

// ====== AUTH HELPERS ======
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, email }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ====== ROUTES ======
app.get('/health', (req, res) => res.json({ ok: true }));

// Auth (email+password; for prod switch to a managed provider or 2FA)
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const info = db.prepare(`INSERT INTO users (email, password_hash) VALUES (?,?)`).run(email, hash);
    const token = jwt.sign({ id: info.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// Get today\'s live item
app.get('/item/today', (req, res) => {
  ensureTodayItem();
  const today = todayStr();
  const item = db.prepare(`SELECT * FROM items WHERE day_date = ? AND status = 'live'`).get(today);
  res.json({ item });
});

// Recent bids
app.get('/bids/recent', (req, res) => {
  const rows = db.prepare(`
    SELECT b.amount, b.created_at, u.email as user, i.name as item
    FROM bids b
    JOIN users u ON u.id = b.user_id
    JOIN items i ON i.id = b.item_id
    ORDER BY b.id DESC
    LIMIT 20
  `).all();
  res.json({ bids: rows });
});

// Place a bid (auth required)
app.post('/bid', authMiddleware, (req, res) => {
  const { amount } = req.body;
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  const today = todayStr();
  const item = db.prepare(`SELECT * FROM items WHERE day_date = ? AND status = 'live'`).get(today);
  if (!item) return res.status(400).json({ error: 'No live item' });
  if (amount <= item.current_bid) return res.status(400).json({ error: `Bid must be higher than ${item.current_bid}` });

  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO bids (item_id, user_id, amount) VALUES (?,?,?)`).run(item.id, req.user.id, amount);
    db.prepare(`UPDATE items SET current_bid = ? WHERE id = ?`).run(amount, item.id);
  });
  tx();
  res.json({ ok: true, current_bid: amount });
});

// Submit an item for review (auth required)
app.post('/submission', authMiddleware, (req, res) => {
  const { name, starting_bid, category, description, image_url } = req.body;
  if (!name || !starting_bid || !category || !description) return res.status(400).json({ error: 'Missing fields' });
  const info = db.prepare(`INSERT INTO submissions (user_id, name, starting_bid, category, description, image_url) VALUES (?,?,?,?,?,?)`)
    .run(req.user.id, name, starting_bid, category, description, image_url || null);
  res.json({ ok: true, id: info.lastInsertRowid });
});

// (Admin) approve next item (for demo: pick oldest pending and schedule for tomorrow)
app.post('/admin/approve-next', (req, res) => {
  // NOTE: add real admin auth in production
  const sub = db.prepare(`SELECT * FROM submissions WHERE status = 'pending' ORDER BY id ASC`).get();
  if (!sub) return res.status(404).json({ error: 'No pending submissions' });
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const day = tomorrow.toISOString().slice(0, 10);
  const info = db.prepare(`INSERT INTO items (name, description, category, image_url, start_bid, current_bid, day_date, status, created_by) VALUES (?,?,?,?,?,?,?,?,NULL)`)
    .run(sub.name, sub.description, sub.category, sub.image_url || null, sub.starting_bid, sub.starting_bid, day, 'queued');
  db.prepare(`UPDATE submissions SET status = 'approved' WHERE id = ?`).run(sub.id);
  res.json({ ok: true, item_id: info.lastInsertRowid, scheduled_for: day });
});

// ====== CRON: at 00:00 switch queued->live and yesterday live->closed ======
cron.schedule('0 0 * * *', () => {
  const today = todayStr();
  // Close yesterday live
  db.prepare(`UPDATE items SET status = 'closed' WHERE status = 'live' AND day_date < ?`).run(today);
  // Promote today queued
  db.prepare(`UPDATE items SET status = 'live' WHERE status = 'queued' AND day_date = ?`).run(today);
  ensureTodayItem();
  console.log(`[cron] Rolled items for ${today}`);
});

app.listen(PORT, () => console.log(`Today’s Item backend running on http://localhost:${PORT}`));
