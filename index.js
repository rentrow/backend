const express   = require('express');
const cors      = require('cors');
const jwt       = require('jsonwebtoken');
const cron      = require('node-cron');
const nodemailer = require('nodemailer');
const crypto    = require('crypto');
const Razorpay  = require('razorpay');
require('dotenv').config();
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app    = express();
app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

const PORT       = process.env.PORT       || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || 'dummy',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'dummy',
});

/* ── Nodemailer (falls back to console in dev) ─────────── */
const IS_DEV_EMAIL =
  !process.env.SMTP_USER || process.env.SMTP_USER === 'your_gmail@gmail.com';

const transporter = IS_DEV_EMAIL
  ? null
  : nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });

async function sendOtpEmail(email, otp, purpose) {
  const html = `
    <div style="font-family:Inter,sans-serif;max-width:480px;margin:0 auto;background:#0a0a0b;color:#fafafa;border-radius:12px;padding:2rem;">
      <h2 style="color:#6366f1;margin-bottom:0.25rem;">RentRow</h2>
      <p style="color:#a1a1aa;margin-top:0">Your ${purpose === 'REGISTER' ? 'sign-up' : 'login'} verification code</p>
      <div style="font-size:2.25rem;font-weight:800;letter-spacing:0.4rem;background:#18181b;padding:1.25rem;border-radius:8px;text-align:center;margin:1.5rem 0;color:#fafafa;">${otp}</div>
      <p style="color:#71717a;font-size:0.85rem;">Expires in ${process.env.OTP_EXPIRE_MINUTES || 10} minutes. Never share this with anyone.</p>
    </div>`;

  if (IS_DEV_EMAIL) {
    console.log('\n' + '═'.repeat(55));
    console.log('📧  EMAIL (DEV MODE — not actually sent)');
    console.log(`    To      : ${email}`);
    console.log(`    Purpose : ${purpose}`);
    console.log(`    🔑 OTP  : ${otp}`);
    console.log('═'.repeat(55) + '\n');
    return;
  }

  await transporter.sendMail({
    from   : `"RentRow" <${process.env.SMTP_USER}>`,
    to     : email,
    subject: `${otp} — Your RentRow verification code`,
    html,
  });
}

/* ── Helpers ────────────────────────────────────────────── */
const generateOtp = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

/* Haversine distance in km */
function haversine(lat1, lng1, lat2, lng2) {
  const R    = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLng = ((lng2 - lng1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/* ── Auth middleware ─────────────────────────────────────── */
const auth = (req, res, next) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'ADMIN') next();
  else res.sendStatus(403);
};

/* ══════════════════════════════════════════════════════════
   AUTH ROUTES
══════════════════════════════════════════════════════════ */

/* Send OTP ─────────────────────────────────────────────── */
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email, purpose = 'REGISTER' } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    // For LOGIN, user must already exist
    if (purpose === 'LOGIN') {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) return res.status(404).json({ error: 'No account found with this email' });
    }

    // Invalidate old OTPs
    await prisma.otpCode.updateMany({
      where: { email, purpose, used: false },
      data:  { used: true },
    });

    const expire  = parseInt(process.env.OTP_EXPIRE_MINUTES || '10');
    const expires = new Date(Date.now() + expire * 60 * 1000);
    const code    = generateOtp();

    await prisma.otpCode.create({ data: { email, code, purpose, expiresAt: expires } });
    await sendOtpEmail(email, code, purpose);

    res.json({
      message  : 'OTP sent to your email',
      dev_otp  : IS_DEV_EMAIL ? code : undefined,   // handy during dev
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* Verify OTP + create/login user ─────────────────────────── */
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, code, purpose, name, phone, role, password } = req.body;
    if (!email || !code) return res.status(400).json({ error: 'Email and OTP are required' });

    const otp = await prisma.otpCode.findFirst({
      where: {
        email,
        code,
        purpose : purpose || 'REGISTER',
        used    : false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!otp) return res.status(400).json({ error: 'Invalid or expired OTP' });

    // Mark used
    await prisma.otpCode.update({ where: { id: otp.id }, data: { used: true } });

    let user;
    if (purpose === 'LOGIN') {
      user = await prisma.user.findUnique({ where: { email } });
      if (!user) return res.status(404).json({ error: 'User not found' });
    } else {
      // REGISTER — create user
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing) return res.status(400).json({ error: 'Email already registered. Please login.' });

      user = await prisma.user.create({
        data: {
          name     : name || 'User',
          email,
          password : password || '',
          phone    : phone || null,
          role     : role  || 'USER',
          verified : true,
        },
      });
    }

    // Mark verified if not already
    if (!user.verified) {
      await prisma.user.update({ where: { id: user.id }, data: { verified: true } });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, phone: user.phone } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* Legacy password login (kept for backward compat) ───────── */
app.post('/api/auth/login', async (req, res) => {
  try {
    const email = req.body.email?.trim();
    const password = req.body.password;

    console.log(`[LOGIN ATTEMPT] Email: '${email}'`);

    // Check if it's the hardcoded admin
    if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
      console.log('=> ADMIN credentials matched');
      const token = jwt.sign(
        { id: 0, email, role: 'ADMIN', name: 'System Admin' },
        JWT_SECRET,
        { expiresIn: '30d' }
      );
      return res.json({ token, user: { id: 0, name: 'System Admin', email, role: 'ADMIN', phone: null } });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || (user.password && user.password !== password && user.password !== ''))
      return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, phone: user.phone } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ══════════════════════════════════════════════════════════
   PROPERTY ROUTES
══════════════════════════════════════════════════════════ */

/* List active properties (with optional proximity filter) ── */
app.get('/api/properties', async (req, res) => {
  try {
    const { type, locality, search, lat, lng, radius = 4 } = req.query;

    const where = { status: 'ACTIVE' };
    if (type) where.type = type;

    // Text search across title / address / locality
    if (search) {
      where.OR = [
        { title:    { contains: search } },
        { address:  { contains: search } },
        { locality: { contains: search } },
      ];
    } else if (locality) {
      where.locality = { contains: locality };
    }

    let properties = await prisma.property.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      include: { owner: { select: { id: true, name: true, phone: true, email: true } } },
    });

    // Parse images JSON string
    properties = properties.map(p => ({
      ...p,
      images: (() => { try { return JSON.parse(p.images); } catch { return []; } })(),
    }));

    // Proximity filter — keep properties within `radius` km
    if (lat && lng) {
      const uLat = parseFloat(lat);
      const uLng = parseFloat(lng);
      const maxKm = parseFloat(radius);
      properties = properties
        .filter(p => {
          if (!p.lat || !p.lng) return false;
          const d = haversine(uLat, uLng, p.lat, p.lng);
          p.distanceKm = Math.round(d * 10) / 10;
          return d <= maxKm;
        })
        .sort((a, b) => a.distanceKm - b.distanceKm);
    }

    res.json(properties);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* Landlord's own listings ─────────────────────────────────── */
app.get('/api/my-listings', auth, async (req, res) => {
  try {
    const properties = await prisma.property.findMany({
      where  : { ownerId: req.user.id },
      orderBy: { createdAt: 'desc' },
    });
    res.json(
      properties.map(p => ({
        ...p,
        images: (() => { try { return JSON.parse(p.images); } catch { return []; } })(),
      }))
    );
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* Create property (PENDING_PAYMENT) ─────────────────────── */
app.post('/api/properties', auth, async (req, res) => {
  try {
    if (req.user.role !== 'LANDLORD')
      return res.status(403).json({ error: 'Only landlords can post listings' });

    const { title, description, type, price, address, locality, lat, lng, images } = req.body;
    const property = await prisma.property.create({
      data: {
        title, description, type, price,
        address,
        locality : locality || null,
        lat, lng,
        images   : JSON.stringify(images || []),
        ownerId  : req.user.id,
        status   : 'PENDING_PAYMENT',
      },
    });
    res.status(201).json(property);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* Delete listing (owner only) ───────────────────────────── */
app.delete('/api/properties/:id', auth, async (req, res) => {
  try {
    const id       = parseInt(req.params.id);
    const property = await prisma.property.findUnique({ where: { id } });
    if (!property || property.ownerId !== req.user.id)
      return res.status(403).json({ error: 'Not authorised' });

    await prisma.message.deleteMany({ where: { propertyId: id } });
    await prisma.property.delete({ where: { id } });
    res.json({ message: 'Listing deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* Mark listing as booked (owner only) ───────────────────── */
app.post('/api/properties/:id/book', auth, async (req, res) => {
  try {
    const id       = parseInt(req.params.id);
    const property = await prisma.property.findUnique({ where: { id } });
    if (!property || property.ownerId !== req.user.id)
      return res.status(403).json({ error: 'Not authorised' });

    const updated = await prisma.property.update({
      where: { id },
      data : { status: 'BOOKED', bookedAt: new Date() },
    });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ── Payment & activate (Razorpay) ──────────────────────── */
app.post('/api/payments/create-order', auth, async (req, res) => {
  try {
    const { propertyId } = req.body;
    const property = await prisma.property.findUnique({ where: { id: propertyId } });
    if (!property || property.ownerId !== req.user.id)
      return res.status(403).json({ error: 'Unauthorized' });
    if (property.status !== 'PENDING_PAYMENT')
      return res.status(400).json({ error: 'Property is not pending payment' });

    const options = {
      amount: 5 * 100, // amount in smallest currency unit (Rs. 5)
      currency: 'INR',
      receipt: `receipt_prop_${propertyId}`,
    };

    const order = await razorpay.orders.create(options);
    res.json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create Razorpay order' });
  }
});

app.post('/api/payments/verify', auth, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, propertyId } = req.body;

    const property = await prisma.property.findUnique({ where: { id: propertyId } });
    if (!property || property.ownerId !== req.user.id)
      return res.status(403).json({ error: 'Unauthorized' });

    const generated_signature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');

    if (generated_signature !== razorpay_signature) {
      return res.status(400).json({ error: 'Payment verification failed' });
    }

    // Success
    await prisma.transaction.create({
      data: {
        propertyId,
        amount: 5,
        status: 'SUCCESS',
        razorpayOrderId: razorpay_order_id,
        razorpayPaymentId: razorpay_payment_id,
      }
    });

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    const updated = await prisma.property.update({
      where: { id: propertyId },
      data: { status: 'ACTIVE', expiresAt },
    });

    res.json({ message: 'Payment successful — listing active for 30 days', property: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ══════════════════════════════════════════════════════════
   MESSAGE ROUTES
══════════════════════════════════════════════════════════ */

/* Inbox — all threads the user is part of ─────────────── */
app.get('/api/messages/inbox', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const msgs = await prisma.message.findMany({
      where  : { OR: [{ senderId: uid }, { receiverId: uid }] },
      orderBy: { createdAt: 'desc' },
      include: {
        property: { select: { id: true, title: true, address: true, images: true, status: true } },
        sender  : { select: { id: true, name: true } },
        receiver: { select: { id: true, name: true } },
      },
    });

    // Group by propertyId → latest message per thread
    const map = new Map();
    for (const m of msgs) {
      if (!map.has(m.propertyId)) {
        const otherId = m.senderId === uid ? m.receiverId : m.senderId;
        const other   = m.senderId === uid ? m.receiver   : m.sender;
        const unread  = msgs.filter(
          x => x.propertyId === m.propertyId && x.receiverId === uid && !x.read
        ).length;

        let coverImage = null;
        try { coverImage = JSON.parse(m.property.images)?.[0] || null; } catch {}

        map.set(m.propertyId, {
          propertyId  : m.propertyId,
          propertyTitle: m.property.title,
          propertyStatus: m.property.status,
          coverImage,
          otherUser   : other,
          lastMessage : m.body,
          lastAt      : m.createdAt,
          unreadCount : unread,
        });
      }
    }

    res.json([...map.values()]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* Thread for a property ─────────────────────────────────── */
app.get('/api/messages/:propertyId', auth, async (req, res) => {
  try {
    const uid        = req.user.id;
    const propertyId = parseInt(req.params.propertyId);

    const messages = await prisma.message.findMany({
      where  : {
        propertyId,
        OR: [{ senderId: uid }, { receiverId: uid }],
      },
      orderBy: { createdAt: 'asc' },
      include: {
        sender  : { select: { id: true, name: true } },
        receiver: { select: { id: true, name: true } },
      },
    });

    // Mark incoming messages as read
    await prisma.message.updateMany({
      where: { propertyId, receiverId: uid, read: false },
      data : { read: true },
    });

    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* Send message ──────────────────────────────────────────── */
app.post('/api/messages', auth, async (req, res) => {
  try {
    const { propertyId, receiverId, body } = req.body;
    if (!body?.trim()) return res.status(400).json({ error: 'Message cannot be empty' });

    const property = await prisma.property.findUnique({ where: { id: propertyId } });
    if (!property) return res.status(404).json({ error: 'Property not found' });

    const msg = await prisma.message.create({
      data   : { propertyId, senderId: req.user.id, receiverId, body: body.trim() },
      include: { sender: { select: { id: true, name: true } } },
    });
    res.status(201).json(msg);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* Unread count ──────────────────────────────────────────── */
app.get('/api/messages/unread-count', auth, async (req, res) => {
  try {
    const count = await prisma.message.count({
      where: { receiverId: req.user.id, read: false },
    });
    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ══════════════════════════════════════════════════════════
   CRON JOB — expire 30-day-old listings
══════════════════════════════════════════════════════════ */
cron.schedule('0 2 * * *', async () => {
  const { count } = await prisma.property.updateMany({
    where: { status: 'ACTIVE', expiresAt: { lt: new Date() } },
    data : { status: 'EXPIRED' },
  });
  if (count > 0) console.log(`[CRON] Expired ${count} listing(s) at ${new Date().toISOString()}`);
});

/* ══════════════════════════════════════════════════════════
   ADMIN ROUTES
══════════════════════════════════════════════════════════ */
app.get('/api/admin/dashboard', auth, isAdmin, async (req, res) => {
  try {
    const usersCount = await prisma.user.count();
    const propertiesCount = await prisma.property.count();
    const activeProperties = await prisma.property.count({ where: { status: 'ACTIVE' } });
    
    // Total revenue
    const tx = await prisma.transaction.aggregate({ _sum: { amount: true }, where: { status: 'SUCCESS' } });
    const revenue = tx._sum.amount || 0;

    res.json({ usersCount, propertiesCount, activeProperties, revenue });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users', auth, isAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: 'desc' },
      select: { id: true, name: true, email: true, phone: true, role: true, verified: true, createdAt: true }
    });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/properties', auth, isAdmin, async (req, res) => {
  try {
    const props = await prisma.property.findMany({
      orderBy: { createdAt: 'desc' },
      include: { owner: { select: { id: true, name: true, email: true } } }
    });
    res.json(props);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/transactions', auth, isAdmin, async (req, res) => {
  try {
    const tx = await prisma.transaction.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(tx);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/', (req, res) => res.send('RentRow API is running ✅'));

app.listen(PORT, () => {
  console.log(`\n🏠 RentRow API → http://localhost:${PORT}`);
  if (IS_DEV_EMAIL) console.log('📧  SMTP: DEV MODE — OTPs printed to console\n');
});
