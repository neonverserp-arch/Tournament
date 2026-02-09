const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

// --- INITIALIZATION ---
// Note: Ensure FIREBASE_SERVICE_ACCOUNT_JSON and CASHFREE_APP_ID/SECRET are in env
const app = express();
app.use(express.json());

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON))
  });
}
const db = admin.firestore();

// --- MIDDLEWARE: AUTHENTICATION ---
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.uid = decodedToken.uid;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// --- API: AUTH ---
app.post('/auth/signup', authenticate, async (req, res) => {
  const { username, email, referralCode } = req.body;
  if (!username || !email) return res.status(400).json({ error: 'Missing fields' });

  const userRef = db.collection('users').doc(req.uid);
  try {
    await db.runTransaction(async (t) => {
      const doc = await t.get(userRef);
      if (doc.exists) return;

      const newReferralCode = Math.random().toString(36).substring(2, 8).toUpperCase();
      t.set(userRef, {
        username,
        email,
        wallet: 0,
        totalXP: 0,
        joinedMatches: [],
        referralCode: newReferralCode,
        referredBy: referralCode || null,
        matchesPlayed: 0,
        totalKills: 0,
        dailyStreak: 0,
        isVIP: false,
        lastDailyReward: 0
      });
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- API: WALLET & CASHFREE ---
app.post('/wallet/createOrder', authenticate, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });

  const orderId = `order_${uuidv4().replace(/-/g, '')}`;
  
  // Mocking Cashfree Order Creation Logic (Requires Cashfree SDK or direct REST call)
  // In production, you'd call https://sandbox.cashfree.com/pg/orders
  const paymentSessionId = "session_" + uuidv4(); 

  try {
    await db.collection('transactions').doc(orderId).set({
      userId: req.uid,
      type: 'DEPOSIT',
      amount: parseFloat(amount),
      status: 'PENDING',
      orderId: orderId,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ orderId, paymentSessionId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/webhook/cashfree', async (req, res) => {
  const signature = req.headers['x-webhook-signature'];
  const payload = JSON.stringify(req.body);
  
  // Verify Cashfree Webhook Signature
  const expectedSignature = crypto
    .createHmac('sha256', process.env.CASHFREE_CLIENT_SECRET)
    .update(payload)
    .digest('base64');

  if (signature !== expectedSignature) return res.status(401).send('Invalid signature');

  const { order, payment } = req.body;
  const orderId = order.order_id;
  const txRef = db.collection('transactions').doc(orderId);

  try {
    await db.runTransaction(async (t) => {
      const txDoc = await t.get(txRef);
      if (!txDoc.exists || txDoc.data().status !== 'PENDING') return;

      const { userId, amount } = txDoc.data();
      const userRef = db.collection('users').doc(userId);

      if (payment.payment_status === 'SUCCESS') {
        t.update(userRef, { wallet: admin.firestore.FieldValue.increment(amount) });
        t.update(txRef, { status: 'SUCCESS' });
      } else {
        t.update(txRef, { status: 'FAILED' });
      }
    });
    res.send('OK');
  } catch (e) {
    res.status(500).send('Retry');
  }
});

app.post('/wallet/withdraw', authenticate, async (req, res) => {
  const { amount, upiId } = req.body;
  const userRef = db.collection('users').doc(req.uid);

  try {
    await db.runTransaction(async (t) => {
      const user = await t.get(userRef);
      if (user.data().wallet < amount) throw new Error('Insufficient balance');

      t.update(userRef, { wallet: admin.firestore.FieldValue.increment(-amount) });
      const txId = uuidv4();
      t.set(db.collection('transactions').doc(txId), {
        userId: req.uid,
        type: 'WITHDRAWAL',
        amount,
        upiId,
        status: 'PENDING',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- API: MATCHES ---
app.post('/match/join', authenticate, async (req, res) => {
  const { matchId, gameUids } = req.body;
  if (!Array.isArray(gameUids) || ![1, 2, 4].includes(gameUids.length)) {
    return res.status(400).json({ error: 'Invalid team size' });
  }

  const matchRef = db.collection('matches').doc(matchId);
  const userRef = db.collection('users').doc(req.uid);
  const teamRef = matchRef.collection('teams').doc(req.uid);

  try {
    await db.runTransaction(async (t) => {
      const match = await t.get(matchRef);
      const user = await t.get(userRef);

      if (!match.exists) throw new Error('Match not found');
      if (match.data().status !== 'upcoming') throw new Error('Registration closed');
      if (match.data().joinedCount + gameUids.length > match.data().maxPlayers) throw new Error('Match full');
      if (user.data().wallet < match.data().entryFee) throw new Error('Insufficient balance');
      if (user.data().joinedMatches.includes(matchId)) throw new Error('Already joined');

      // Check for duplicate gameUids in sub-collection (Manual Check)
      const existingTeams = await t.get(matchRef.collection('teams'));
      const allGameUids = [];
      existingTeams.forEach(doc => allGameUids.push(...doc.data().gameUids));
      if (gameUids.some(uid => allGameUids.includes(uid))) throw new Error('Game UID already registered');

      t.update(userRef, {
        wallet: admin.firestore.FieldValue.increment(-match.data().entryFee),
        joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
      });

      t.update(matchRef, { joinedCount: admin.firestore.FieldValue.increment(gameUids.length) });

      t.set(teamRef, {
        ownerUid: req.uid,
        ownerUsername: user.data().username,
        gameUids: gameUids
      });
    });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- API: REWARDS ---
app.post('/rewards/daily', authenticate, async (req, res) => {
  const userRef = db.collection('users').doc(req.uid);
  const now = Date.now();

  try {
    await db.runTransaction(async (t) => {
      const user = await t.get(userRef);
      const lastReward = user.data().lastDailyReward || 0;

      if (now - lastReward < 24 * 60 * 60 * 1000) throw new Error('Reward already claimed');

      t.update(userRef, {
        wallet: admin.firestore.FieldValue.increment(10),
        dailyStreak: admin.firestore.FieldValue.increment(1),
        lastDailyReward: now
      });

      t.set(db.collection('transactions').doc(uuidv4()), {
        userId: req.uid,
        type: 'DAILY_REWARD',
        amount: 10,
        status: 'SUCCESS',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- ADMIN API: DISTRIBUTION ---
app.post('/admin/match/distribute', async (req, res) => {
  const { matchId, gameUid, rank, kills } = req.body;
  const matchRef = db.collection('matches').doc(matchId);

  try {
    await db.runTransaction(async (t) => {
      const match = await t.get(matchRef);
      if (!match.exists || match.data().prizeDistributed) throw new Error('Invalid or processed match');

      const teamsSnap = await t.get(matchRef.collection('teams'));
      let targetTeam = null;
      teamsSnap.forEach(doc => {
        if (doc.data().gameUids.includes(gameUid)) targetTeam = doc.data();
      });

      if (!targetTeam) throw new Error('Game UID not found in match');

      const userRef = db.collection('users').doc(targetTeam.ownerUid);
      const user = await t.get(userRef);

      const perKill = match.data().perKillRate || 0;
      const rankPrize = match.data().rankPrizes?.[rank] || 0;
      const totalPrize = (kills * perKill) + rankPrize;
      const xpGained = (kills * 10) + (rank === 1 ? 100 : 20);

      t.update(userRef, {
        wallet: admin.firestore.FieldValue.increment(totalPrize),
        totalXP: admin.firestore.FieldValue.increment(xpGained),
        matchesPlayed: admin.firestore.FieldValue.increment(1),
        totalKills: admin.firestore.FieldValue.increment(kills)
      });

      t.set(db.collection('transactions').doc(uuidv4()), {
        userId: targetTeam.ownerUid,
        type: 'PRIZE',
        amount: totalPrize,
        status: 'SUCCESS',
        matchId,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
