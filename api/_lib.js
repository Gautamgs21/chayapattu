// Shared helpers. Files starting with "_" are not exposed as API routes.
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');

const TZ = process.env.APP_TIMEZONE || 'Asia/Kolkata';

// Reuse one MongoDB connection across invocations (important on serverless)
const cache = global._ledgerlyMongo || (global._ledgerlyMongo = { promise: null });

async function getDb() {
  if (!cache.promise) {
    const client = new MongoClient(process.env.MONGO_URI);
    cache.promise = client.connect().then(async (c) => {
      const db = c.db();
      await db.collection('users').createIndex({ username: 1 }, { unique: true });
      await db.collection('transactions').createIndex({ date: -1 });
      return db;
    }).catch((e) => { cache.promise = null; throw e; });
  }
  return cache.promise;
}

const oid = (id) => { try { return new ObjectId(String(id)); } catch { return null; } };
const pub = (u) => ({ id: String(u._id), name: u.name, username: u.username, role: u.role });
const validUsername = (u) => /^[a-z0-9._-]{3,30}$/.test(u || '');
const send = (res, code, body) => res.status(code).json(body);
const fail = (res, code, message) => send(res, code, { message });

// Date/time in the app's timezone (default India), not the server's UTC
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: TZ });          // YYYY-MM-DD
const nowTime = () => new Date().toLocaleTimeString('en-GB', { timeZone: TZ, hour: '2-digit', minute: '2-digit' });

// ---- session cookie (httpOnly JWT) ----
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
const cookieFlags = () => `HttpOnly; Path=/; SameSite=Strict${process.env.VERCEL ? '; Secure' : ''}`;

function setSession(res, user) {
  const token = jwt.sign({ id: String(user._id) }, process.env.JWT_SECRET, { expiresIn: '24h' });
  res.setHeader('Set-Cookie', `sid=${token}; Max-Age=86400; ${cookieFlags()}`);
}
function clearSession(res) {
  res.setHeader('Set-Cookie', `sid=; Max-Age=0; ${cookieFlags()}`);
}

async function getUser(req, db) {
  try {
    const { id } = jwt.verify(parseCookies(req).sid || '', process.env.JWT_SECRET);
    return await db.collection('users').findOne({ _id: oid(id), active: { $ne: false } });
  } catch { return null; }
}

// Returns the signed-in user, or sends 401 and returns null
async function requireUser(req, res, db) {
  const u = await getUser(req, db);
  if (!u) fail(res, 401, 'Please sign in.');
  return u;
}

// Wraps a handler with error handling
const handler = (fn) => async (req, res) => {
  try {
    if (!process.env.MONGO_URI || !process.env.JWT_SECRET) return fail(res, 500, 'Server is not configured (missing environment variables).');
    await fn(req, res, await getDb());
  } catch (e) {
    console.error(e);
    fail(res, 500, 'Server error. Please try again.');
  }
};

module.exports = { getDb, oid, pub, validUsername, send, fail, today, nowTime, TZ, setSession, clearSession, getUser, requireUser, handler };
