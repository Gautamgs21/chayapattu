require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const client = new MongoClient(process.env.MONGO_URI);
const SECRET = process.env.JWT_SECRET;
const COOKIE = { httpOnly: true, sameSite: 'strict', secure: process.env.COOKIE_SECURE === 'true', maxAge: 24 * 3600 * 1000 };
let users, txs;

// ---------- helpers ----------
const wrap = (fn) => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ message: 'Server error.' }); });
const bad = (res, code, message) => res.status(code).json({ message });
const pub = (u) => ({ id: String(u._id), name: u.name, username: u.username, role: u.role });
const oid = (id) => { try { return new ObjectId(String(id)); } catch { return null; } };
const validUsername = (u) => /^[a-z0-9._-]{3,30}$/.test(u || '');
const today = () => new Date().toISOString().slice(0, 10);
const nowTime = () => new Date().toTimeString().slice(0, 5);
const setCookie = (res, u) => res.cookie('sid', jwt.sign({ id: String(u._id) }, SECRET, { expiresIn: '24h' }), COOKIE);

async function auth(req, res, next) {
  try {
    const { id } = jwt.verify(req.cookies.sid || '', SECRET);
    const u = await users.findOne({ _id: oid(id), active: { $ne: false } });
    if (!u) throw new Error();
    req.user = u; next();
  } catch { bad(res, 401, 'Please sign in.'); }
}
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : bad(res, 403, 'Admins only.');

// ---------- auth ----------
app.get('/api/auth/me', wrap(async (req, res) => {
  if (await users.countDocuments() === 0) return res.json({ setupRequired: true });
  try {
    const { id } = jwt.verify(req.cookies.sid || '', SECRET);
    const u = await users.findOne({ _id: oid(id), active: { $ne: false } });
    if (u) return res.json({ authenticated: true, user: pub(u) });
  } catch {}
  res.json({ authenticated: false });
}));

app.post('/api/auth/setup', wrap(async (req, res) => {
  if (await users.countDocuments() > 0) return bad(res, 403, 'Setup already completed.');
  const { name, username, password } = req.body;
  if (!name || !validUsername(username) || String(password || '').length < 8) return bad(res, 400, 'Invalid details.');
  const doc = { name: name.trim(), username, passwordHash: await bcrypt.hash(password, 12), role: 'admin', active: true };
  doc._id = (await users.insertOne(doc)).insertedId;
  setCookie(res, doc); res.json({ user: pub(doc) });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const { username, password } = req.body;
  const u = await users.findOne({ username: String(username || '').toLowerCase(), active: { $ne: false } });
  if (!u || !(await bcrypt.compare(String(password || ''), u.passwordHash))) return bad(res, 401, 'Invalid username or password.');
  setCookie(res, u); res.json({ user: pub(u) });
}));

app.post('/api/auth/logout', (req, res) => { res.clearCookie('sid'); res.json({ success: true }); });

app.post('/api/auth/change-password', auth, wrap(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (String(newPassword || '').length < 8) return bad(res, 400, 'New password must be at least 8 characters.');
  if (!(await bcrypt.compare(String(currentPassword || ''), req.user.passwordHash))) return bad(res, 400, 'Current password is incorrect.');
  await users.updateOne({ _id: req.user._id }, { $set: { passwordHash: await bcrypt.hash(newPassword, 12) } });
  res.json({ success: true, message: 'Password updated.' });
}));

// ---------- members ----------
app.get('/api/members', auth, wrap(async (req, res) => {
  res.json((await users.find({ active: { $ne: false } }).sort({ name: 1 }).toArray()).map(pub));
}));

app.post('/api/members', auth, adminOnly, wrap(async (req, res) => {
  const { name, username, password, role } = req.body;
  if (!name || !validUsername(username) || String(password || '').length < 8) return bad(res, 400, 'Invalid details.');
  if (await users.findOne({ username })) return bad(res, 409, 'That username is taken.');
  await users.insertOne({ name: name.trim(), username, passwordHash: await bcrypt.hash(password, 12), role: role === 'admin' ? 'admin' : 'member', active: true });
  res.json({ success: true, message: `${name} added.` });
}));

app.put('/api/members/:id', auth, wrap(async (req, res) => {
  const id = oid(req.params.id); const isSelf = String(req.user._id) === req.params.id;
  if (!id || (!isSelf && req.user.role !== 'admin')) return bad(res, 403, 'Not allowed.');
  const set = {};
  if (req.body.name) set.name = req.body.name.trim();
  if (req.body.role && req.user.role === 'admin' && !isSelf) set.role = req.body.role === 'admin' ? 'admin' : 'member';
  if (req.body.password) { if (req.body.password.length < 8) return bad(res, 400, 'Password too short.'); set.passwordHash = await bcrypt.hash(req.body.password, 12); }
  await users.updateOne({ _id: id }, { $set: set });
  if (set.name) await txs.updateMany({ personId: req.params.id }, { $set: { person: set.name } });
  res.json({ success: true, message: 'Member updated.' });
}));

app.delete('/api/members/:id', auth, adminOnly, wrap(async (req, res) => {
  if (String(req.user._id) === req.params.id) return bad(res, 400, "You can't remove yourself.");
  await users.updateOne({ _id: oid(req.params.id) }, { $set: { active: false } });
  res.json({ success: true, message: 'Member removed.' });
}));

// ---------- transactions ----------
async function buildTx(t, reg) {
  const p = await users.findOne({ _id: oid(t.personId) });
  const amount = Number(t.amount);
  if (!p || !(amount > 0)) return null;
  return { personId: String(p._id), person: p.name, type: t.type === 'Credit' ? 'Credit' : 'Debit',
    category: t.category || (t.type === 'Credit' ? 'Top Up' : 'Others'), amount,
    date: t.date || today(), time: nowTime(), notes: String(t.notes || '').slice(0, 100),
    registrar: reg.name, registrarId: String(reg._id), createdAt: new Date() };
}
const outTx = ({ _id, createdAt, ...t }) => ({ id: String(_id), ...t });

app.post('/api/transactions', auth, wrap(async (req, res) => {
  const doc = await buildTx(req.body, req.user);
  if (!doc) return bad(res, 400, 'Invalid transaction.');
  await txs.insertOne(doc);
  res.json({ success: true, message: `${doc.type} of ₹${doc.amount} added for ${doc.person}.` });
}));

app.post('/api/transactions/bulk', auth, wrap(async (req, res) => {
  const docs = (await Promise.all((req.body.transactions || []).map(t => buildTx(t, req.user)))).filter(Boolean);
  if (!docs.length) return bad(res, 400, 'No valid transactions.');
  await txs.insertMany(docs);
  res.json({ success: true, message: `${docs.length} transactions added.` });
}));

app.get('/api/transactions', auth, wrap(async (req, res) => {
  const q = {};
  if (req.query.personId) q.personId = String(req.query.personId);
  if (req.query.date) q.date = String(req.query.date);
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  res.json((await txs.find(q).sort({ date: -1, createdAt: -1 }).limit(limit).toArray()).map(outTx));
}));

async function deleteTxs(req, ids) {
  const q = { _id: { $in: ids.map(oid).filter(Boolean) } };
  if (req.user.role !== 'admin') q.registrarId = String(req.user._id);   // members delete only their own
  return (await txs.deleteMany(q)).deletedCount;
}
app.delete('/api/transactions/:id', auth, wrap(async (req, res) => {
  const n = await deleteTxs(req, [req.params.id]);
  n ? res.json({ success: true, message: 'Transaction deleted.' }) : bad(res, 403, 'Not allowed or not found.');
}));
app.post('/api/transactions/bulk-delete', auth, wrap(async (req, res) => {
  const n = await deleteTxs(req, req.body.ids || []);
  res.json({ success: true, message: `${n} transactions deleted.` });
}));

// ---------- dashboard ----------
app.get('/api/dashboard', auth, wrap(async (req, res) => {
  const ms = await users.find({ active: { $ne: false } }).sort({ name: 1 }).toArray();
  const all = await txs.find().toArray();
  const bal = {}, cats = {}, monthly = { ALL: {} };
  let td = 0, tc = 0;
  const monthsList = []; const now = new Date();
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    monthsList.push({ key: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`, label: d.toLocaleString('en', { month: 'short' }) });
  }
  ms.forEach(m => { monthly[m.name] = {}; });
  for (const t of all) {
    if (t.type === 'Credit') { tc += t.amount; bal[t.personId] = (bal[t.personId] || 0) + t.amount; continue; }
    td += t.amount; bal[t.personId] = (bal[t.personId] || 0) - t.amount;
    cats[t.category] = (cats[t.category] || 0) + t.amount;
    const k = (t.date || '').slice(0, 7);
    monthly.ALL[k] = (monthly.ALL[k] || 0) + t.amount;
    if (monthly[t.person]) monthly[t.person][k] = (monthly[t.person][k] || 0) + t.amount;
  }
  res.json({
    members: ms.map(m => ({ id: String(m._id), name: m.name, balance: bal[String(m._id)] || 0 })),
    summary: { totalDebit: td, totalCredit: tc, netBalance: tc - td },
    categories: Object.entries(cats).map(([category, amount]) => ({ category, amount })).sort((a, b) => b.amount - a.amount),
    monthly: { monthsList, data: monthly }
  });
}));

client.connect().then(async () => {
  const db = client.db();
  users = db.collection('users'); txs = db.collection('transactions');
  await users.createIndex({ username: 1 }, { unique: true });
  await txs.createIndex({ date: -1 });
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`LEDGERLY running at http://localhost:${port}/ledgerly.html`));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
