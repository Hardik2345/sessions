// server.js
import express from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { z } from 'zod';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
app.use(helmet());
app.use(express.json({ limit: '256kb' }));

app.use(cors({
  origin: true, // reflect request origin; tighten to exact origins if desired
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Collector-Key', 'X-Brand'],
  maxAge: 86400
}));
app.options('/collect', cors());

// ---------- Env ----------
const {
  MONGO_URI,
  PORT = 3000,
  COLLECTOR_KEY,
  COLLECTOR_KEYS // JSON map: {"brandA":"keyA","brandB":"keyB"}
} = process.env;

const KEY_MAP = (() => { try { return COLLECTOR_KEYS ? JSON.parse(COLLECTOR_KEYS) : null; } catch { return null; }})();
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

// ---------- Schemas & Models ----------
const sessionSchema = new mongoose.Schema({
  brand_id: { type: String, required: true, index: true },
  session_id: { type: String, required: true, unique: true, index: true },
  actor_id: { type: String, required: true, index: true },
  started_at: { type: Date, required: true, index: true },
  last_event_at: { type: Date, required: true },
  landing_url: { type: String },
  landing_referrer: { type: String },
  utm_source: String,
  utm_medium: String,
  utm_campaign: String,
  utm_term: String,
  utm_content: String
}, { versionKey: false, collection: 'sessions' });

sessionSchema.index({ actor_id: 1, last_event_at: -1 });
// TTL (6h)
sessionSchema.index({ last_event_at: 1 }, { expireAfterSeconds: 21600 });
// Helpful compunds
sessionSchema.index({ brand_id: 1, started_at: 1 });
sessionSchema.index({ brand_id: 1, actor_id: 1, last_event_at: -1 });

const eventSchema = new mongoose.Schema({
  brand_id: { type: String, required: true, index: true },
  event_id: { type: String, required: true, unique: true },
  session_id: { type: String, index: true },
  event_name: { type: String, required: true, index: true },
  occurred_at: { type: Date, required: true },
  url: { type: String },
  referrer: { type: String },
  user_agent: { type: String },
  client_id: { type: String, index: true },
  visitor_id: { type: String, index: true },
  raw: { type: mongoose.Schema.Types.Mixed }
}, { versionKey: false, collection: 'events' });

eventSchema.index({ session_id: 1, occurred_at: 1 });
// ✅ brand-scoped unique dedupe for ATC (engages only when both keys are strings)
eventSchema.index(
  { brand_id: 1, session_id: 1, event_name: 1, "raw.product_id": 1 },
  {
    unique: true,
    partialFilterExpression: {
      event_name: "product_added_to_cart",
      session_id: { $type: "string" },
      "raw.product_id": { $type: "string" }
    }
  }
);
// TTL (6h)
eventSchema.index({ occurred_at: 1 }, { expireAfterSeconds: 21600 });
// Helpful compunds
eventSchema.index({ brand_id: 1, event_name: 1, occurred_at: 1 });
eventSchema.index({ brand_id: 1, session_id: 1, occurred_at: 1 });

const Session = mongoose.model('Session', sessionSchema);
const Event = mongoose.model('Event', eventSchema);

// ---------- Validation ----------
const EventSchema = z.object({
  event_id: z.string(),
  event_name: z.string(),
  occurred_at: z.string(),               // ISO string from client
  session_id: z.string().nullable().optional(),
  client_id: z.string().nullable(),
  visitor_id: z.string().nullable(),
  url: z.string().url().nullable(),
  referrer: z.string().nullable(),
  user_agent: z.string().nullable(),
  data: z.any().optional()
});

// ---------- Helpers ----------
const safe = v => (v === undefined ? null : v);

function getHeader(req, name) {
  const v = req.get(name);
  return typeof v === 'string' ? v.trim() : null;
}

// auth via headers OR query (?brand=&k=)
function pickAuth(req) {
  let brand = getHeader(req, 'X-Brand');
  let key   = getHeader(req, 'X-Collector-Key');
  if (!brand) brand = (req.query.brand ?? req.query.b)?.toString().trim() || null;
  if (!key)   key   = (req.query.k ?? req.query.key)?.toString().trim() || null;
  return { brand, key };
}

function brandAuth(req, res, next) {
  const { brand, key } = pickAuth(req);
  if (!brand) return res.status(400).json({ error: 'missing brand' });

  const expected = KEY_MAP ? KEY_MAP[brand] : (COLLECTOR_KEY || null);
  if (!expected || key !== expected) {
    console.warn('auth_fail', { path: req.path, brand, hasKey: Boolean(key) });
    return res.sendStatus(401);
  }
  req.brand = brand;
  next();
}

function parseUTM(u) {
  try {
    if (!u) return {};
    const url = new URL(u);
    const get = k => url.searchParams.get(k) || undefined;
    return {
      utm_source: get('utm_source'),
      utm_medium: get('utm_medium'),
      utm_campaign: get('utm_campaign'),
      utm_term: get('utm_term'),
      utm_content: get('utm_content')
    };
  } catch { return {}; }
}

// Normalize Shopify gid -> "ProductVariant:123"
function normalizeShopifyId(id) {
  if (!id) return null;
  const s = String(id);
  if (s.includes('/')) {
    const parts = s.split('/');
    const kind = parts.at(-2);
    const num  = parts.at(-1);
    return `${kind}:${num}`;
  }
  return s;
}

// Deterministic session fallback (keeps dedupe working even without client vp_sid)
function deriveSid(brand, actor, when) {
  const bucket = Math.floor(when.getTime() / SESSION_TIMEOUT_MS); // 30-min bucket
  return crypto.createHash('sha1').update(`${brand}|${actor}|${bucket}`).digest('hex');
}

// If product_id still missing, synthesize a short, stable string so the unique index engages
function synthPid(brand, sessionId, e) {
  const src = `${brand}|${sessionId || "nosid"}|${e.event_id}|${e.url || ""}`;
  return "SYNTH:" + crypto.createHash('sha1').update(src).digest('hex').slice(0, 16);
}

// ---------- Routes ----------
app.post('/collect', brandAuth, async (req, res) => {
  try {
    const normalized = {
      ...req.body,
      client_id: safe(req.body.client_id),
      visitor_id: safe(req.body.visitor_id),
      session_id: req.body.session_id ?? null,
      url: safe(req.body.url),
      referrer: safe(req.body.referrer),
      user_agent: safe(req.body.user_agent)
    };
    const e = EventSchema.parse(normalized);

    const when = new Date(e.occurred_at);
    if (isNaN(when.getTime())) return res.sendStatus(400);

    const actor = e.visitor_id || e.client_id || null;

    // Choose a session id: prefer client vp_sid; fall back to deterministic server sid
    let sessionId = e.session_id || null;
    if (!sessionId && actor) {
      sessionId = deriveSid(req.brand, actor, when);
    }

    // Upsert session when we have an id; use $max for last_event_at
    if (sessionId) {
      const utm = parseUTM(e.url);
      await Session.updateOne(
        { brand_id: req.brand, session_id: sessionId },
        {
          $setOnInsert: {
            brand_id: req.brand,
            session_id: sessionId,
            actor_id: actor || 'unknown',
            started_at: when,
            landing_url: e.url || null,
            landing_referrer: e.referrer || null,
            ...utm
          },
          $max: { last_event_at: when }
        },
        { upsert: true }
      );
    }

    // Ensure productId is a non-null string for ATC dedupe
    let productId = normalizeShopifyId(e?.data?.product_id ?? null);
    if (!productId) productId = synthPid(req.brand, sessionId, e);

    // Write event: ATC has dedupe path keyed on (brand, session_id, event_name, raw.product_id)
    if (e.event_name === 'product_added_to_cart' && sessionId && productId) {
      await Event.updateOne(
        { brand_id: req.brand, session_id: sessionId, event_name: e.event_name, "raw.product_id": productId },
        {
          $setOnInsert: {
            brand_id: req.brand,
            event_id: e.event_id,
            session_id: sessionId,
            event_name: e.event_name,
            occurred_at: when,
            url: e.url || null,
            referrer: e.referrer || null,
            user_agent: e.user_agent || null,
            client_id: e.client_id || null,
            visitor_id: e.visitor_id || null,
            raw: { ...(e.data ?? {}), product_id: productId }
          }
        },
        { upsert: true }
      );
    } else {
      // generic idempotent write (replays collapse on event_id)
      await Event.updateOne(
        { event_id: e.event_id },
        {
          $setOnInsert: {
            brand_id: req.brand,
            event_id: e.event_id,
            session_id: sessionId,
            event_name: e.event_name,
            occurred_at: when,
            url: e.url || null,
            referrer: e.referrer || null,
            user_agent: e.user_agent || null,
            client_id: e.client_id || null,
            visitor_id: e.visitor_id || null,
            raw: e.data ?? null
          }
        },
        { upsert: true }
      );
    }

    res.sendStatus(204);
  } catch (err) {
    console.error(err);
    res.sendStatus(400);
  }
});

// ---------- Metrics ----------
app.get('/metrics/sessions', brandAuth, async (req, res) => {
  try {
    const from = req.query.from ? new Date(req.query.from) : new Date(Date.now() - 24 * 60 * 60 * 1000);
    const to   = req.query.to   ? new Date(req.query.to)   : new Date();
    const count = await Session.countDocuments({ brand_id: req.brand, started_at: { $gte: from, $lt: to } });
    res.json({ brand: req.brand, from, to, sessions: count });
  } catch {
    res.status(400).json({ error: 'bad range' });
  }
});

app.get('/metrics/sessions/:timestamp', brandAuth, async (req, res) => {
  try {
    const { timestamp } = req.params;
    const eventName = (req.query.eventName || 'product_added_to_cart').toString();

    let ts;
    if (/^\d+$/.test(timestamp)) {
      const n = Number(timestamp);
      const ms = timestamp.length === 10 ? n * 1000 : n;
      ts = new Date(ms);
    } else {
      ts = new Date(timestamp);
    }
    if (isNaN(ts.getTime())) return res.status(400).json({ error: 'invalid timestamp' });

    const [totalSessions, totalEvents] = await Promise.all([
      Session.countDocuments({ brand_id: req.brand, started_at: { $gt: ts } }),
      Event.countDocuments({ brand_id: req.brand, event_name: eventName, occurred_at: { $gt: ts } })
    ]);

    res.json({ brand: req.brand, from: ts, eventName, totalSessions, totalEvents });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'internal' });
  }
});

app.get('/healthz', (_, res) => res.json({ ok: true }));

// ---------- Bootstrap ----------
(async () => {
  await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    maxPoolSize: 10
  });
  try {
    await Session.syncIndexes();
    await Event.syncIndexes();
  } catch (e) {
    console.warn('Index sync failed:', e?.message || e);
  }
  app.listen(PORT, () => console.log(`collector listening on :${PORT}`));
})();
