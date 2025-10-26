// server.js
import express from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { z } from 'zod';
import { v4 as uuid } from 'uuid';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
app.use(helmet());
app.use(express.json({ limit: '256kb' }));

app.use(cors({
  origin: true,
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Collector-Key', 'X-Brand'],
  maxAge: 86400
}));

app.options('/collect', cors());

const { MONGO_URI, PORT = 3000, COLLECTOR_KEY, COLLECTOR_KEYS } = process.env;

// ---------- Mongo models ----------
const sessionSchema = new mongoose.Schema({
  brand_id: { type: String, required: true, index: true },
  session_id: { type: String, required: true, index: true, unique: true },
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

// TTL indexes (6h)
sessionSchema.index({ last_event_at: 1 }, { expireAfterSeconds: 21600 });

// Useful compound indexes
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

// ✅ brand-scoped ATC dedupe w/ partial filter (requires strings)
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

// Additional helpful indexes
eventSchema.index({ brand_id: 1, event_name: 1, occurred_at: 1 });
eventSchema.index({ brand_id: 1, session_id: 1, occurred_at: 1 });

const Session = mongoose.model('Session', sessionSchema);
const Event = mongoose.model('Event', eventSchema);

// ---------- Validation ----------
const BaseEventSchema = z.object({
  event_id: z.string(),
  event_name: z.string(),
  occurred_at: z.string(), // ISO timestamp from client
  session_id: z.string().nullable().optional(), // NEW: accept client session id
  client_id: z.string().nullable(),
  visitor_id: z.string().nullable(),
  url: z.string().url().nullable(),
  referrer: z.string().nullable(),
  user_agent: z.string().nullable(),
  data: z.any().optional()
});

// ---------- Helpers ----------
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

const KEY_MAP = (() => {
  try { return COLLECTOR_KEYS ? JSON.parse(COLLECTOR_KEYS) : null; } catch { return null; }
})();

const safe = (v) => (v === undefined ? null : v);

function brandAuth(req, res, next) {
  const brand = req.get('X-Brand');
  const key = req.get('X-Collector-Key');
  if (!brand) return res.status(400).json({ error: 'missing brand' });

  if (KEY_MAP) {
    const expected = KEY_MAP[brand];
    if (!expected || key !== expected) return res.sendStatus(401);
  } else {
    if (!COLLECTOR_KEY || key !== COLLECTOR_KEY) return res.sendStatus(401);
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

// Normalize Shopify gid -> stable string "ProductVariant:123" or "Product:456"
function normalizeShopifyId(id) {
  if (!id) return null;
  try {
    const s = String(id);
    if (s.includes('/')) {
      const parts = s.split('/');
      const kind = parts.at(-2);
      const num = parts.at(-1);
      return `${kind}:${num}`;
    }
    return s;
  } catch { return String(id); }
}

// Deterministic session id fallback when client didn't send vp_sid
function deriveSid(brand, actor, when) {
  const bucket = Math.floor(when.getTime() / SESSION_TIMEOUT_MS); // 30-min bucket
  return crypto.createHash('sha1').update(`${brand}|${actor}|${bucket}`).digest('hex');
}

// ---------- Routes ----------
app.post('/collect', brandAuth, async (req, res) => {
  try {
    // sanitize/normalize body first
    const normalized = {
      ...req.body,
      client_id: safe(req.body.client_id),
      visitor_id: safe(req.body.visitor_id),
      session_id: req.body.session_id ?? null,
      url: safe(req.body.url),
      referrer: safe(req.body.referrer),
      user_agent: safe(req.body.user_agent)
    };
    const e = BaseEventSchema.parse(normalized);

    const when = new Date(e.occurred_at);
    if (isNaN(when.getTime())) return res.sendStatus(400);

    const actor = e.visitor_id || e.client_id || null;

    // 1) choose session id
    let sessionId = e.session_id || null;
    if (!sessionId && actor) {
      sessionId = deriveSid(req.brand, actor, when);
    }

    // 2) upsert session if we have one
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
          $max: { last_event_at: when } // out-of-order safe
        },
        { upsert: true }
      );
    }

    // 3) normalized product id for ATC dedupe
    const productId = normalizeShopifyId(e.data?.product_id ?? null);

    // 4) write event (ATC has special dedupe path)
    if (e.event_name === "product_added_to_cart" && sessionId && productId) {
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
            raw: e.data ?? null,
            why_no_session: sessionId ? null : (actor ? "server_derived" : "no_actor")
          }
        },
        { upsert: true }
      );
    }

    return res.sendStatus(204);
  } catch (err) {
    console.error(err);
    return res.sendStatus(400);
  }
});

// ---------- Metrics ----------
app.get('/metrics/sessions', brandAuth, async (req, res) => {
  try {
    const from = req.query.from ? new Date(req.query.from) : new Date(Date.now() - 24 * 60 * 60 * 1000);
    const to = req.query.to ? new Date(req.query.to) : new Date();
    const count = await Session.countDocuments({ brand_id: req.brand, started_at: { $gte: from, $lt: to } });
    res.json({ brand: req.brand, from, to, sessions: count });
  } catch (e) {
    res.status(400).json({ error: 'bad range' });
  }
});

app.get('/metrics/sessions/:timestamp', brandAuth, async (req, res) => {
  try {
    const { timestamp } = req.params;
    const eventName = (req.query.eventName || 'product_added_to_cart').toString(); // default fixed

    let ts;
    if (/^\d+$/.test(timestamp)) {
      const n = Number(timestamp);
      const ms = timestamp.length === 10 ? n * 1000 : n;
      ts = new Date(ms);
    } else {
      ts = new Date(timestamp);
    }
    if (isNaN(ts.getTime())) {
      return res.status(400).json({ error: 'invalid timestamp' });
    }

    const [totalSessions, totalEvents] = await Promise.all([
      Session.countDocuments({ brand_id: req.brand, started_at: { $gt: ts } }),
      Event.countDocuments({ brand_id: req.brand, event_name: eventName, occurred_at: { $gt: ts } })
    ]);

    return res.json({ brand: req.brand, from: ts, eventName, totalSessions, totalEvents });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal' });
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
  app.listen(PORT, () => console.log(`collector on :${PORT}`));
})();
