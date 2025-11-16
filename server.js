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
  origin: true,  
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
  session_sig: { type: String, index: true }, // race-proof signature for a landing
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
sessionSchema.index({ last_event_at: 1 }, { expireAfterSeconds: 86400 }); // TTL 24h
sessionSchema.index({ brand_id: 1, started_at: 1 });
sessionSchema.index({ brand_id: 1, actor_id: 1, last_event_at: -1 });
sessionSchema.index(
  { brand_id: 1, actor_id: 1, session_sig: 1 },
  { unique: true, partialFilterExpression: { session_sig: { $type: "string" } } }
);

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
eventSchema.index({ occurred_at: 1 }, { expireAfterSeconds: 86400 }); // TTL 24h
eventSchema.index({ brand_id: 1, event_name: 1, occurred_at: 1 });
eventSchema.index({ brand_id: 1, session_id: 1, occurred_at: 1 });

const Session = mongoose.model('Session', sessionSchema);
const Event = mongoose.model('Event', eventSchema);

// ---------- Validation ----------
const EventSchema = z.object({
  event_id: z.string(),
  event_name: z.string(),
  occurred_at: z.string(),               // ISO string
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
const hostOf = (u) => { try { return u ? new URL(u).host : null; } catch { return null; } };

function getHeader(req, name) { const v = req.get(name); return typeof v === 'string' ? v.trim() : null; }
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
  if (!expected || key !== expected) return res.sendStatus(401);
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

// Shopify gid → "ProductVariant:123"
function normalizeShopifyId(id) {
  if (!id) return null;
  const s = String(id);
  if (s.includes('/')) { const parts = s.split('/'); return `${parts.at(-2)}:${parts.at(-1)}`; }
  return s;
}

// Fallback ONLY for continuing sessions without client session_id
function deriveSid(brand, actor, when) {
  const bucket = Math.floor(when.getTime() / SESSION_TIMEOUT_MS);
  return crypto.createHash('sha1').update(`${brand}|${actor}|${bucket}`).digest('hex');
}

// Deterministic product id if missing
function synthPid(brand, sessionId, e) {
  const src = `${brand}|${sessionId || "nosid"}|${e.event_id}|${e.url || ""}`;
  return "SYNTH:" + crypto.createHash('sha1').update(src).digest('hex').slice(0, 16);
}

// Landing signature (bucket × utm trio × external ref host)
function makeSessionSig(when, url, referrer, utm) {
  const bucket = Math.floor(when.getTime() / SESSION_TIMEOUT_MS);
  const urlHost = hostOf(url);
  const refHost = hostOf(referrer);
  const extRef = (refHost && urlHost && refHost !== urlHost) ? refHost : 'direct';
  const src = [
    bucket,
    (utm.utm_source || '-').toLowerCase(),
    (utm.utm_medium || '-').toLowerCase(),
    (utm.utm_campaign || '-').toLowerCase(),
    extRef.toLowerCase()
  ].join('|');
  return crypto.createHash('sha1').update(src).digest('hex');
}

// Source-class mapping & UTM key
function sourceClassFromHost(h) {
  if (!h) return 'direct';
  const s = h.toLowerCase();
  if (/(^|\.)instagram\.com$/.test(s) || /(^|\.)facebook\.com$/.test(s) || /^fb(\.|$)/.test(s) || /(^|\.)l\.facebook\.com$/.test(s) || /(^|\.)l\.instagram\.com$/.test(s) || /(^|\.)m\.facebook\.com$/.test(s))
    return 'facebook';
  if (/(^|\.)google\./.test(s)) return 'google';
  if (/(^|\.)bing\.com$/.test(s)) return 'bing';
  return 'other';
}
function utmKey(utm) {
  const a = (utm.utm_source||'').trim().toLowerCase();
  const b = (utm.utm_medium||'').trim().toLowerCase();
  const c = (utm.utm_campaign||'').trim().toLowerCase();
  return (a||b||c) ? `${a}|${b}|${c}` : null; // null = no campaign
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

    // --- Current request features ---
    const isPV = e.event_name === 'page_viewed';
    const utmNow = parseUTM(e.url);
    const urlHostNow = hostOf(e.url);
    const refHostNow = hostOf(e.referrer);
    const externalRef = !!(refHostNow && urlHostNow && refHostNow !== urlHostNow);
    const refClassNow = externalRef ? sourceClassFromHost(refHostNow) : 'direct';
    const utmNowKey = utmKey(utmNow);

    let sessionId = e.session_id || null;

    if (actor) {
      const recent = await Session.findOne({ actor_id: actor, brand_id: req.brand })
        .sort({ last_event_at: -1 })
        .lean();

      const within30m = !!(recent && (when - new Date(recent.last_event_at) <= SESSION_TIMEOUT_MS));

      // --- Previous session features ---
      const prevRefHost  = hostOf(recent?.landing_referrer || null);
      const prevUrlHost  = hostOf(recent?.landing_url || null);
      const prevExternal = !!(prevRefHost && prevUrlHost && prevRefHost !== prevUrlHost);
      const prevRefClass = prevExternal ? sourceClassFromHost(prevRefHost) : 'direct';
      const prevUtmKey   = utmKey({
        utm_source: recent?.utm_source,
        utm_medium: recent?.utm_medium,
        utm_campaign: recent?.utm_campaign
      });

      // Debounce to avoid rapid IG/FB ↔ app hops for source-only changes
      const startedAgoMs = recent ? (when - new Date(recent.started_at)) : Number.POSITIVE_INFINITY;
      const debounceMs = 5 * 60 * 1000;

      // Split rules (only considered on PV)
      const utmChanged    = isPV && !!utmNowKey && (utmNowKey !== prevUtmKey);
      const sourceChanged = isPV && (refClassNow !== prevRefClass) &&
                            refClassNow !== 'direct' && prevRefClass !== 'direct' &&
                            (startedAgoMs >= debounceMs);

      const shouldSplit = within30m && (utmChanged || sourceChanged);

      if (!recent || !within30m || shouldSplit) {
        // NEW session; fresh UUID; session_sig prevents race double-creates
        const sig = makeSessionSig(when, e.url, e.referrer, utmNow);
        const base = { brand_id: req.brand, actor_id: actor, session_sig: sig };

        async function upsertSessionWithNewId() {
          const sid = crypto.randomUUID();
          const up = await Session.findOneAndUpdate(
            base,
            {
              $setOnInsert: {
                ...base,
                session_id: sid,
                started_at: when,
                landing_url: e.url || null,
                landing_referrer: e.referrer || null,
                utm_source: utmNow.utm_source || null,
                utm_medium: utmNow.utm_medium || null,
                utm_campaign: utmNow.utm_campaign || null,
                utm_term: utmNow.utm_term || null,
                utm_content: utmNow.utm_content || null
              },
              $max: { last_event_at: when } // creates/updates last_event_at
            },
            { upsert: true, new: true }
          ).lean();
          return up.session_id;
        }

        try {
          sessionId = await upsertSessionWithNewId();
        } catch (err) {
          if (err?.code === 11000 && err?.keyPattern?.session_id) {
            // extremely rare: retry once on session_id collision
            sessionId = await upsertSessionWithNewId();
          } else {
            throw err;
          }
        }
      } else {
        // Continue existing session; if client didn't send session_id, derive fallback
        sessionId = sessionId || recent.session_id || deriveSid(req.brand, actor, when);
        await Session.updateOne(
          { brand_id: req.brand, session_id: sessionId },
          { $max: { last_event_at: when } }
        );
      }
    }

    // --- ATC write path (requires session + product) ---
    let productId = normalizeShopifyId(e?.data?.product_id ?? null);
    if (!productId) productId = synthPid(req.brand, sessionId, e);

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
      // generic idempotent event write
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
    const eventName = 'product_added_to_cart';

    // Parse timestamp (supports both epoch and ISO)
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

    // Optional ?to=<time> upper bound, defaults to now
    const to = req.query.to ? new Date(req.query.to) : new Date();
    if (isNaN(to.getTime())) {
      return res.status(400).json({ error: 'invalid to timestamp' });
    }

    // Prepare both queries (but don't await yet)
    const sessionsPromise = Session.countDocuments({
      brand_id: req.brand,
      started_at: { $gt: ts, $lte: to }
    });

    const atcSessionsPromise = Event.aggregate([
      {
        $match: {
          brand_id: req.brand,
          event_name: eventName,
          occurred_at: { $gt: ts, $lte: to },
          session_id: { $type: 'string' }
        }
      },
      { $group: { _id: '$session_id' } },
      { $count: 'unique_atc_sessions' }
    ]);

    // Run in parallel
    const [totalSessions, atcAgg] = await Promise.all([sessionsPromise, atcSessionsPromise]);

    const totalAtcSessions = atcAgg?.[0]?.unique_atc_sessions || 0;

    res.json({
      brand: req.brand,
      from: ts,
      to,
      eventName,
      totalSessions,
      totalEvents:totalAtcSessions
    });
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
