import express from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { z } from 'zod';
import { v4 as uuid } from 'uuid';
import cors from 'cors';

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

// ✅ new: dedupe ATC by product_id per session
eventSchema.index(
  { session_id: 1, event_name: 1, "raw.product_id": 1 },
  { unique: true, partialFilterExpression: { event_name: "product_added_to_cart" } }
);

// TTL indexes
sessionSchema.index({ last_event_at: 1 }, { expireAfterSeconds: 21600 });
eventSchema.index({ occurred_at: 1 }, { expireAfterSeconds: 21600 });

sessionSchema.index({ brand_id: 1, started_at: 1 });
sessionSchema.index({ brand_id: 1, actor_id: 1, last_event_at: -1 });
eventSchema.index({ brand_id: 1, event_name: 1, occurred_at: 1 });
eventSchema.index({ brand_id: 1, session_id: 1, occurred_at: 1 });

const Session = mongoose.model('Session', sessionSchema);
const Event = mongoose.model('Event', eventSchema);

// ---------- Validation ----------
const EventSchema = z.object({
  event_id: z.string(),
  event_name: z.string(),
  occurred_at: z.string(),
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

// ---------- Routes ----------
app.post('/collect', brandAuth, async (req, res) => {
  try {
    console.log("Received event:", req.body);
    const e = EventSchema.parse(req.body);
    const when = new Date(e.occurred_at);
    const actor = e.visitor_id || e.client_id;

    let sessionId = null;
    if (actor) {
      const recent = await Session.findOne({ actor_id: actor, brand_id: req.brand })
        .sort({ last_event_at: -1 })
        .lean();

      if (!recent || (when - new Date(recent.last_event_at)) > SESSION_TIMEOUT_MS) {
        sessionId = uuid();
        const utm = parseUTM(e.url);
        await Session.create({
          brand_id: req.brand,
          session_id: sessionId,
          actor_id: actor,
          started_at: when,
          last_event_at: when,
          landing_url: e.url || null,
          landing_referrer: e.referrer || null,
          ...utm
        });
      } else {
        sessionId = recent.session_id;
        await Session.updateOne(
          { session_id: sessionId, brand_id: req.brand },
          { $set: { last_event_at: when } }
        );
      }
    }

    // ✅ dedupe logic
    if (e.event_name === "product_added_to_cart") {
      const productId = e.data?.product_id || null;
      await Event.updateOne(
        { session_id: sessionId, event_name: e.event_name, "raw.product_id": productId },
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
            raw: e.data ?? null
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
    const eventName = (req.query.eventName || 'add_to_cart').toString();

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

    const totalSessionsPromise = Session.countDocuments({ brand_id: req.brand, started_at: { $gt: ts } });
    const totalEventsPromise = Event.countDocuments({
      brand_id: req.brand,
      event_name: eventName,
      occurred_at: { $gt: ts }
    });

    const [totalSessions, totalEvents] = await Promise.all([totalSessionsPromise, totalEventsPromise]);

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
