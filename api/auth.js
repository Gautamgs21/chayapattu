const bcrypt = require('bcryptjs');
const L = require('./_lib');

module.exports = L.handler(async (req, res, db) => {
  const users = db.collection('users');
  const route = req.query.r;
  const body = req.body || {};

  // Who am I? Also tells the page whether first-time setup is needed.
  if (route === 'me' && req.method === 'GET') {
    if ((await users.countDocuments()) === 0) return L.send(res, 200, { setupRequired: true });
    const u = await L.getUser(req, db);
    return L.send(res, 200, u ? { authenticated: true, user: L.pub(u) } : { authenticated: false });
  }

  // First-run: create the admin account (only while the database has no users)
  if (route === 'setup' && req.method === 'POST') {
    if ((await users.countDocuments()) > 0) return L.fail(res, 403, 'Setup already completed.');
    const name = String(body.name || '').trim();
    const username = String(body.username || '').toLowerCase();
    if (!name || !L.validUsername(username) || String(body.password || '').length < 8) return L.fail(res, 400, 'Please check the details you entered.');
    const doc = { name, username, passwordHash: await bcrypt.hash(body.password, 12), role: 'admin', active: true };
    doc._id = (await users.insertOne(doc)).insertedId;
    L.setSession(res, doc);
    return L.send(res, 200, { user: L.pub(doc) });
  }

  if (route === 'login' && req.method === 'POST') {
    const u = await users.findOne({ username: String(body.username || '').toLowerCase(), active: { $ne: false } });
    const okPw = u && (await bcrypt.compare(String(body.password || ''), u.passwordHash));
    if (!okPw) return L.fail(res, 401, 'Invalid username or password.');
    L.setSession(res, u);
    return L.send(res, 200, { user: L.pub(u) });
  }

  if (route === 'logout' && req.method === 'POST') {
    L.clearSession(res);
    return L.send(res, 200, { success: true });
  }

  if (route === 'change-password' && req.method === 'POST') {
    const me = await L.requireUser(req, res, db); if (!me) return;
    if (String(body.newPassword || '').length < 8) return L.fail(res, 400, 'New password must be at least 8 characters.');
    if (!(await bcrypt.compare(String(body.currentPassword || ''), me.passwordHash))) return L.fail(res, 400, 'Current password is incorrect.');
    await users.updateOne({ _id: me._id }, { $set: { passwordHash: await bcrypt.hash(body.newPassword, 12) } });
    return L.send(res, 200, { success: true, message: 'Password updated.' });
  }

  return L.fail(res, 404, 'Not found.');
});
