const L = require('./_lib');

module.exports = L.handler(async (req, res, db) => {
  const users = db.collection('users');
  const txs = db.collection('transactions');
  const me = await L.requireUser(req, res, db); if (!me) return;
  const route = req.query.r;
  const body = req.body || {};

  const buildTx = async (t) => {
    const p = await users.findOne({ _id: L.oid(t.personId) });
    const amount = Number(t.amount);
    if (!p || !(amount > 0)) return null;
    return {
      personId: String(p._id), person: p.name,
      type: t.type === 'Credit' ? 'Credit' : 'Debit',
      category: String(t.category || (t.type === 'Credit' ? 'Top Up' : 'Others')).slice(0, 30),
      amount, date: t.date || L.today(), time: L.nowTime(),
      notes: String(t.notes || '').slice(0, 100),
      registrar: me.name, registrarId: String(me._id), createdAt: new Date()
    };
  };
  const outTx = ({ _id, createdAt, ...t }) => ({ id: String(_id), ...t });
  // Members may delete only their own entries; admins can delete any
  const deleteTxs = async (ids) => {
    const q = { _id: { $in: ids.map(L.oid).filter(Boolean) } };
    if (me.role !== 'admin') q.registrarId = String(me._id);
    return (await txs.deleteMany(q)).deletedCount;
  };

  // ---------- Dashboard ----------
  if (route === 'dashboard' && req.method === 'GET') {
    const ms = await users.find({ active: { $ne: false } }).sort({ name: 1 }).toArray();
    const all = await txs.find().toArray();
    const bal = {}, cats = {}, monthly = { ALL: {} };
    let td = 0, tc = 0;

    const [y, m] = L.today().split('-').map(Number);
    const monthsList = [];
    for (let i = 5; i >= 0; i--) {
      const d = new Date(Date.UTC(y, m - 1 - i, 1));
      monthsList.push({ key: d.toISOString().slice(0, 7), label: d.toLocaleString('en', { month: 'short', timeZone: 'UTC' }) });
    }
    ms.forEach((u) => { monthly[u.name] = {}; });

    for (const t of all) {
      if (t.type === 'Credit') { tc += t.amount; bal[t.personId] = (bal[t.personId] || 0) + t.amount; continue; }
      td += t.amount; bal[t.personId] = (bal[t.personId] || 0) - t.amount;
      cats[t.category] = (cats[t.category] || 0) + t.amount;
      const k = String(t.date || '').slice(0, 7);
      monthly.ALL[k] = (monthly.ALL[k] || 0) + t.amount;
      if (monthly[t.person]) monthly[t.person][k] = (monthly[t.person][k] || 0) + t.amount;
    }
    return L.send(res, 200, {
      members: ms.map((u) => ({ id: String(u._id), name: u.name, balance: bal[String(u._id)] || 0 })),
      summary: { totalDebit: td, totalCredit: tc, netBalance: tc - td },
      categories: Object.entries(cats).map(([category, amount]) => ({ category, amount })).sort((a, b) => b.amount - a.amount),
      monthly: { monthsList, data: monthly }
    });
  }

  // ---------- Transactions ----------
  if (route === 'tx' && req.method === 'GET') {
    const q = {};
    if (req.query.personId) q.personId = String(req.query.personId);
    if (req.query.date) q.date = String(req.query.date);
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const list = await txs.find(q).sort({ date: -1, createdAt: -1 }).limit(limit).toArray();
    return L.send(res, 200, list.map(outTx));
  }

  if (route === 'tx' && req.method === 'POST') {
    const doc = await buildTx(body);
    if (!doc) return L.fail(res, 400, 'Invalid transaction.');
    await txs.insertOne(doc);
    return L.send(res, 200, { success: true, message: `${doc.type} of ₹${doc.amount} added for ${doc.person}.` });
  }

  if (route === 'tx' && req.method === 'DELETE') {
    const n = await deleteTxs([req.query.id]);
    return n ? L.send(res, 200, { success: true, message: 'Transaction deleted.' }) : L.fail(res, 403, 'Not allowed, or already deleted.');
  }

  if (route === 'bulk' && req.method === 'POST') {
    const docs = (await Promise.all((body.transactions || []).map(buildTx))).filter(Boolean);
    if (!docs.length) return L.fail(res, 400, 'No valid transactions.');
    await txs.insertMany(docs);
    return L.send(res, 200, { success: true, message: `${docs.length} transactions added.` });
  }

  if (route === 'bulk-delete' && req.method === 'POST') {
    const n = await deleteTxs(body.ids || []);
    return L.send(res, 200, { success: true, message: `${n} transactions deleted.` });
  }

  return L.fail(res, 404, 'Not found.');
});
