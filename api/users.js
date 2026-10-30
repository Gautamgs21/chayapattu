const bcrypt = require('bcryptjs');
const L = require('./_lib');

module.exports = L.handler(async (req, res, db) => {
  const users = db.collection('users');
  const me = await L.requireUser(req, res, db); if (!me) return;
  const isAdmin = me.role === 'admin';
  const body = req.body || {};
  const id = req.query.id;

  // List members
  if (req.method === 'GET' && !id) {
    const list = await users.find({ active: { $ne: false } }).sort({ name: 1 }).toArray();
    return L.send(res, 200, list.map(L.pub));
  }

  // Add member (admin only)
  if (req.method === 'POST' && !id) {
    if (!isAdmin) return L.fail(res, 403, 'Admins only.');
    const name = String(body.name || '').trim();
    const username = String(body.username || '').toLowerCase();
    if (!name || !L.validUsername(username) || String(body.password || '').length < 8) return L.fail(res, 400, 'Please check the details you entered.');
    if (await users.findOne({ username })) return L.fail(res, 409, 'That username is already taken.');
    await users.insertOne({ name, username, passwordHash: await bcrypt.hash(body.password, 12), role: body.role === 'admin' ? 'admin' : 'member', active: true });
    return L.send(res, 200, { success: true, message: `${name} added.` });
  }

  // Edit member (admin, or the person themselves)
  if (req.method === 'PUT' && id) {
    const isSelf = String(me._id) === id;
    if (!L.oid(id) || (!isSelf && !isAdmin)) return L.fail(res, 403, 'Not allowed.');
    const set = {};
    if (body.name) set.name = String(body.name).trim();
    if (body.role && isAdmin && !isSelf) set.role = body.role === 'admin' ? 'admin' : 'member';
    if (body.password) {
      if (String(body.password).length < 8) return L.fail(res, 400, 'Password must be at least 8 characters.');
      set.passwordHash = await bcrypt.hash(body.password, 12);
    }
    await users.updateOne({ _id: L.oid(id) }, { $set: set });
    if (set.name) await db.collection('transactions').updateMany({ personId: id }, { $set: { person: set.name } });
    return L.send(res, 200, { success: true, message: 'Member updated.' });
  }

  // Remove member (admin only). Their past transactions are kept.
  if (req.method === 'DELETE' && id) {
    if (!isAdmin) return L.fail(res, 403, 'Admins only.');
    if (String(me._id) === id) return L.fail(res, 400, "You can't remove your own account.");
    await users.updateOne({ _id: L.oid(id) }, { $set: { active: false } });
    return L.send(res, 200, { success: true, message: 'Member removed.' });
  }

  return L.fail(res, 405, 'Method not allowed.');
});
