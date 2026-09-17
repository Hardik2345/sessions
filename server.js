// server.js
import express from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { z } from 'zod';
import cors from 'cors';
import crypto from 'crypto';
import SlugCache from './slugCache.model.js';
import ClickEvent from './clickEvent.model.js';
import ActorCursor from './actorCursor.model.js';
import SessionHistory from './sessionHistory.model.js';
import { getBrandCredentials, refreshBrandCredentials } from './brandCredentials.js';

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
  SESSION_TIMEOUT = 1800 // seconds; default 30 min
} = process.env;

const SESSION_TIMEOUT_MS = Number(SESSION_TIMEOUT) * 1000;

// Schedule brand-credential refreshes for the start of each day (server's
// local time — on Render this is UTC unless configured otherwise), rather
// than a fixed interval from whenever the process happened to start.
// Recomputes "next midnight" fresh each time so day-length changes (DST)
// don't cause drift.
function msUntilNextMidnight() {
  const now = new Date();
  const next = new Date(now);
  next.setHours(24, 0, 0, 0);
  return next.getTime() - now.getTime();
}

function scheduleDailyBrandRefresh() {
  setTimeout(async () => {
    try {
      await refreshBrandCredentials();
    } catch (err) {
      console.error('[brandCredentials] scheduled daily refresh failed, keeping last-known-good cache:', err.message);
    }
    scheduleDailyBrandRefresh();
  }, msUntilNextMidnight());
}

// Two events belonging to the same page load/action can legitimately arrive
// at the server out of order relative to their own client-side timestamps
// (normal network/scheduling jitter — not a bug in the pixel). A small
// negative gap is tolerated as "still the same session" instead of forcing
// an incorrect split; anything beyond this is treated as a genuinely
// out-of-order event and still starts a new session (see resolveSessionTiming).
const NEGATIVE_GAP_TOLERANCE_MS = 30 * 1000;

// ---------- Per-actor async lock ----------
// resolveSessionTiming (read the cursor) and commitSessionCursor (write it)
// are two separate operations. Without this, two /collect requests for the
// SAME actor arriving within milliseconds of each other (very common — a
// single page load often fires several analytics events almost
// simultaneously) can race: both read the cursor before either writes back,
// and whichever writes last can silently clobber the other's update
// (lost events_seq entries, incorrect session_start, etc). This serializes
// the read-decide-write-close cycle per actor so that can't happen.
const actorLocks = new Map(); // key: "brand|actor_id" -> tail promise (never rejects)

function withActorLock(key, fn) {
  const prevTail = actorLocks.get(key) || Promise.resolve();
  const result = prevTail.then(fn);
  const tail = result.then(() => {}, () => {});
  actorLocks.set(key, tail);
  tail.finally(() => {
    if (actorLocks.get(key) === tail) actorLocks.delete(key);
  });
  return result;
}

// ---------- Schemas & Models ----------
//
// DISABLED: server-side session persistence/stitching.
// We no longer write to a `sessions` collection — every event/click now
// trusts the `session_id` and `actor_id` sent by the pixel as-is, the same
// way click events already worked. actor_id is a pixel-generated, cookie-
// persisted identifier (valid ~1 year) that replaces the old
// visitor_id||client_id derivation. Left here, commented out, in case this
// needs to be revisited.
//
// const SESSION_TIMEOUT_MS = 30 * 60 * 1000;
//
// const sessionSchema = new mongoose.Schema({
//   brand_id: { type: String, required: true, index: true },
//   session_id: { type: String, required: true, unique: true, index: true },
//   actor_id: { type: String, required: true, index: true },
//   session_sig: { type: String, index: true }, // race-proof signature for a landing
//   started_at: { type: Date, required: true, index: true },
//   last_event_at: { type: Date, required: true },
//   landing_url: { type: String },
//   landing_referrer: { type: String },
//   utm_source: String,
//   utm_medium: String,
//   utm_campaign: String,
//   utm_term: String,
//   utm_content: String
// }, { versionKey: false, collection: 'sessions' });
//
// sessionSchema.index({ actor_id: 1, last_event_at: -1 });
// sessionSchema.index({ last_event_at: 1 }, { expireAfterSeconds: 129600 }); // TTL 36h
// sessionSchema.index({ brand_id: 1, started_at: 1 });
// sessionSchema.index({ brand_id: 1, actor_id: 1, last_event_at: -1 });
// sessionSchema.index(
//   { brand_id: 1, actor_id: 1, session_sig: 1 },
//   { unique: true, partialFilterExpression: { session_sig: { $type: "string" } } }
// );
//
// const Session = mongoose.model('Session', sessionSchema);

const eventSchema = new mongoose.Schema({
  brand_id: { type: String, required: true, index: true },
  event_id: { type: String, required: true },
  session_id: { type: String, index: true },
  actor_id: { type: String, default: null, index: true },
  event_name: { type: String, required: true, index: true },
  occurred_at: { type: Date, required: true },
  url: { type: String },
  referrer: { type: String },
  user_agent: { type: String },
  client_id: { type: String, index: true },
  visitor_id: { type: String, index: true },
  session_start: { type: Date, default: null },
  session_end: { type: Date, default: null },
  session_time_spent: { type: Number, default: null }, // milliseconds
  raw: { type: mongoose.Schema.Types.Mixed }
}, { versionKey: false, collection: 'events', timestamps: true });

eventSchema.index({ session_id: 1, occurred_at: 1 });
eventSchema.index(
  { event_id: 1 },
  { unique: true, partialFilterExpression: { event_id: { $type: "string" } } }
);
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
// TTL index intentionally not declared here — managed manually. If it's
// created directly in MongoDB (not through this schema), see the note above
// the bootstrap's syncIndexes() calls: syncIndexes() drops any index that
// exists in the DB but isn't declared in the schema, so a manually-added
// TTL index could get removed on the next deploy unless that's accounted for.
eventSchema.index({ brand_id: 1, event_name: 1, occurred_at: 1 });
eventSchema.index({ brand_id: 1, session_id: 1, occurred_at: 1 });
eventSchema.index({ brand_id: 1, actor_id: 1, occurred_at: 1 });

const Event = mongoose.model('Event', eventSchema);

// ---------- Validation ----------
// small helper: extract product/collection slug from common Shopify URL patterns
function parseShopifySlug(url) {
  if (!url) return null;
  try {
    const u = new URL(url, 'http://x');
    const p = u.pathname || '';
    const prod = p.match(/\/products\/([a-zA-Z0-9\-_.]+)/);
    if (prod) return { type: 'product', slug: prod[1] };
    const coll = p.match(/\/collections\/([a-zA-Z0-9\-_.]+)/);
    if (coll) return { type: 'collection', slug: coll[1] };
    const handle = u.searchParams.get('handle');
    if (handle) return { type: 'product', slug: handle };
    return null;
  } catch {
    return null;
  }
}

const EventSchema = z.object({
  event_id: z.string(),
  event_name: z.string(),
  occurred_at: z.string(),               // ISO string
  session_id: z.string().nullable().optional(),
  actor_id: z.string().nullable().optional(),
  client_id: z.string().nullable(),
  visitor_id: z.string().nullable(),
  url: z.string().url().nullable(),
  referrer: z.string().nullable(),
  user_agent: z.string().nullable(),
  data: z.any().optional(),
  slug_info: z.any().optional()
});

const ClickDataSchema = z.object({
  x: z.number().nullable().default(null),
  y: z.number().nullable().default(null),
  tag_name: z.string().nullable().default(null),
  element_id: z.string().nullable().default(null),
  element_name: z.string().nullable().default(null),
  element_type: z.string().nullable().default(null),
  element_value: z.string().nullable().default(null),
  href: z.string().nullable().default(null)
});

const ClickSignalsSchema = z.object({
  url_changed: z.boolean(),
  cart_changed: z.boolean(),
  ui_changed: z.boolean(),
  meaningful_scroll: z.boolean()
});

const ClickEventSchema = z.object({
  event_id: z.string(),
  event_name: z.literal('click'),
  occurred_at: z.string(),
  client_id: z.string().nullable(),
  visitor_id: z.string().nullable(),
  session_id: z.string().nullable(),
  actor_id: z.string().nullable().optional(),
  url: z.string().url().nullable(),
  referrer: z.string().nullable(),
  user_agent: z.string().nullable(),
  data: z.object({
    click: ClickDataSchema,
    signals: ClickSignalsSchema
  })
});

// ---------- Helpers ----------
const safe = v => (v === undefined ? null : v);

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
  if (!brand) {
    console.warn('[auth] rejected: missing brand', { path: req.path, ip: req.ip });
    return res.status(400).json({ error: 'missing brand' });
  }
  const creds = getBrandCredentials(brand);
  const expected = creds ? creds.intent_tracking_token : null;
  if (!expected || key !== expected) {
    console.warn('[auth] rejected: bad key', { brand, path: req.path, ip: req.ip });
    return res.sendStatus(401);
  }
  req.brand = brand;
  req.brandCreds = creds;
  next();
}

// DISABLED (session-stitching only, see note above): parseUTM, hostOf,
// deriveSid, makeSessionSig, sourceClassFromHost, utmKey.
//
// function parseUTM(u) {
//   try {
//     if (!u) return {};
//     const url = new URL(u);
//     const get = k => url.searchParams.get(k) || undefined;
//     return {
//       utm_source: get('utm_source'),
//       utm_medium: get('utm_medium'),
//       utm_campaign: get('utm_campaign'),
//       utm_term: get('utm_term'),
//       utm_content: get('utm_content')
//     };
//   } catch { return {}; }
// }
//
// const hostOf = (u) => { try { return u ? new URL(u).host : null; } catch { return null; } };

// Shopify gid → "ProductVariant:123"
function normalizeShopifyId(id) {
  if (!id) return null;
  const s = String(id);
  if (s.includes('/')) { const parts = s.split('/'); return `${parts.at(-2)}:${parts.at(-1)}`; }
  return s;
}

// Identify synthetic fallback product IDs sent by the pixel
const isFallbackId = (id) =>
  typeof id === 'string' && id.startsWith('FALLBACK:');

// function deriveSid(brand, actor, when) {
//   const bucket = Math.floor(when.getTime() / SESSION_TIMEOUT_MS);
//   return crypto.createHash('sha1').update(`${brand}|${actor}|${bucket}`).digest('hex');
// }

// Deterministic product id if missing
function synthPid(brand, sessionId, e) {
  const src = `${brand}|${sessionId || "nosid"}|${e.event_id}|${e.url || ""}`;
  return "SYNTH:" + crypto.createHash('sha1').update(src).digest('hex').slice(0, 16);
}

// function makeSessionSig(when, url, referrer, utm) {
//   const bucket = Math.floor(when.getTime() / SESSION_TIMEOUT_MS);
//   const urlHost = hostOf(url);
//   const refHost = hostOf(referrer);
//   const extRef = (refHost && urlHost && refHost !== urlHost) ? refHost : 'direct';
//   const src = [
//     bucket,
//     (utm.utm_source || '-').toLowerCase(),
//     (utm.utm_medium || '-').toLowerCase(),
//     (utm.utm_campaign || '-').toLowerCase(),
//     extRef.toLowerCase()
//   ].join('|');
//   return crypto.createHash('sha1').update(src).digest('hex');
// }
//
// function sourceClassFromHost(h) {
//   if (!h) return 'direct';
//   const s = h.toLowerCase();
//   if (/(^|\.)instagram\.com$/.test(s) || /(^|\.)facebook\.com$/.test(s) || /^fb(\.|$)/.test(s) || /(^|\.)l\.facebook\.com$/.test(s) || /(^|\.)l\.instagram\.com$/.test(s) || /(^|\.)m\.facebook\.com$/.test(s))
//     return 'facebook';
//   if (/(^|\.)google\./.test(s)) return 'google';
//   if (/(^|\.)bing\.com$/.test(s)) return 'bing';
//   return 'other';
// }
// function utmKey(utm) {
//   const a = (utm.utm_source||'').trim().toLowerCase();
//   const b = (utm.utm_medium||'').trim().toLowerCase();
//   const c = (utm.utm_campaign||'').trim().toLowerCase();
//   return (a||b||c) ? `${a}|${b}|${c}` : null; // null = no campaign
// }

// Reinterprets a real UTC instant's wall-clock time in the store's timezone
// as if it were UTC — i.e. bakes the store's local time into the Date value
// purely for display purposes on the `occurred_at` field. All internal logic
// (session-gap math, the actor cursor, TTL indexes) must keep using the true
// instant (`when`), never this transformed value, or their math breaks.
function toStoreLocalOccurredAt(date, ianaTimezone) {
  if (!ianaTimezone) return date;
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: ianaTimezone,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false
    }).formatToParts(date);
    const get = (type) => parts.find(p => p.type === type)?.value;
    const year = Number(get('year'));
    const month = Number(get('month'));
    const day = Number(get('day'));
    let hour = Number(get('hour'));
    if (hour === 24) hour = 0; // some locales report midnight as 24
    const minute = Number(get('minute'));
    const second = Number(get('second'));
    return new Date(Date.UTC(year, month - 1, day, hour, minute, second, date.getUTCMilliseconds()));
  } catch (err) {
    console.error('[timezone] failed to convert occurred_at for timezone', ianaTimezone, err.message);
    return date;
  }
}

// A click is "useful" if it produced any observable effect
function classifyClick(signals) {
  const s = signals || {};
  const useful = !!(s.url_changed || s.cart_changed || s.ui_changed || s.meaningful_scroll);
  return useful ? 'useful_click' : 'dead_click';
}

// ---------- Session timing (per-actor, across events + click_events) ----------
// Decide this event's session_id/session_start/session_end/session_time_spent
// using a tiny per-actor cursor (see actorCursor.model.js). session_id is
// server-generated (not trusted from the pixel) and follows the same
// SESSION_TIMEOUT window as session_start/session_end — a new session_id is
// minted whenever a new session starts, and reused for as long as the actor
// keeps sending events within the timeout. session_time_spent is always null
// for the event being processed right now — it only ever gets filled in
// retroactively, on a session's actual last event, once a later event
// reveals the session has closed (see commitSessionCursor below).
async function resolveSessionTiming(brand, actorId, when) {
  if (!actorId) {
    return { session_id: crypto.randomUUID(), session_start: when, session_end: null, session_time_spent: null, cursor: null, isNewSession: true };
  }

  const cursor = await ActorCursor.findOne({ brand_id: brand, actor_id: actorId }).lean();
  const gap = cursor ? (when - new Date(cursor.last_event_at)) : Infinity;
  // A small negative gap (event arrived out of order relative to its own
  // timestamp — normal jitter, not a real return-visit) is tolerated as
  // still the same session. Only a gap beyond the timeout, in either
  // direction, actually starts a new session.
  const isNewSession = !cursor || gap > SESSION_TIMEOUT_MS || gap < -NEGATIVE_GAP_TOLERANCE_MS;

  if (isNewSession) {
    return { session_id: crypto.randomUUID(), session_start: when, session_end: null, session_time_spent: null, cursor, isNewSession: true };
  }

  return {
    session_id: cursor.session_id,
    session_start: new Date(cursor.session_start),
    session_end: when,
    session_time_spent: null,
    cursor,
    isNewSession: false
  };
}

// Only call this once the event has actually been newly inserted (not a
// duplicate/no-op upsert) — otherwise a retried event_id would corrupt the
// timeline or double-close a session.
async function commitSessionCursor(brand, actorId, timing, when, docRef, eventDoc) {
  if (!actorId) return;

  if (timing.isNewSession && timing.cursor) {
    const prevSessionStart = new Date(timing.cursor.session_start);
    const prevLastEventAt = new Date(timing.cursor.last_event_at);
    const prevSessionTimeSpent = prevLastEventAt - prevSessionStart;
    const PrevModel = timing.cursor.last_ref.collection === 'click_events' ? ClickEvent : Event;

    try {
      await PrevModel.updateOne(
        { event_id: timing.cursor.last_ref.event_id },
        { $set: { session_end: prevLastEventAt, session_time_spent: prevSessionTimeSpent } }
      );
    } catch (err) {
      console.error('[session] failed to close previous session:', err);
    }

    // Permanent historical record of the just-closed session — actor_cursors
    // itself is about to be overwritten with the new session's state below,
    // so this is the only place the completed session's events_seq survives.
    try {
      const ianaTz = getBrandCredentials(brand)?.store_timezone_iana;
      const displayOccurredAt = toStoreLocalOccurredAt(prevLastEventAt, ianaTz);

      await SessionHistory.create({
        brand_id: brand,
        actor_id: actorId,
        session_id: timing.cursor.session_id,
        session_start: prevSessionStart,
        session_end: prevLastEventAt,
        session_time_spent: prevSessionTimeSpent,
        occurred_at: displayOccurredAt,
        events_seq: timing.cursor.events_seq || {},
        last_ref: timing.cursor.last_ref
      });
    } catch (err) {
      console.error('[session] failed to write session history:', err);
    }
  }

  // events_seq tracks the CURRENT (still-open) session's journey only —
  // resets on a new session, otherwise appends the next step. Stores the
  // full event document (not just its name) for each step.
  let eventsSeq;
  if (timing.isNewSession) {
    eventsSeq = { '1': eventDoc };
  } else {
    const prevSeq = timing.cursor?.events_seq || {};
    const nextKey = String(Object.keys(prevSeq).length + 1);
    eventsSeq = { ...prevSeq, [nextKey]: eventDoc };
  }

  // Never let a tolerated out-of-order (but still-same-session) event move
  // the cursor's "latest known event" pointer backward — otherwise a later
  // event that arrives first, followed by an earlier-timestamped one, would
  // wrongly become the session's closing event/timestamp.
  let newLastEventAt = when;
  let newLastRef = docRef;
  if (!timing.isNewSession && timing.cursor) {
    const prevLastEventAt = new Date(timing.cursor.last_event_at);
    if (prevLastEventAt > when) {
      newLastEventAt = prevLastEventAt;
      newLastRef = timing.cursor.last_ref;
    }
  }

  try {
    await ActorCursor.updateOne(
      { brand_id: brand, actor_id: actorId },
      { $set: { session_id: timing.session_id, session_start: timing.session_start, last_event_at: newLastEventAt, last_ref: newLastRef, events_seq: eventsSeq } },
      { upsert: true }
    );
  } catch (err) {
    console.error('[session] failed to update actor cursor:', err);
  }
}

// Build & log the document we will insert on first write
function buildInsertDoc(brand, e, sessionId, actorId, when, productIdOverride, timing, displayOccurredAt) {
  const baseRaw = e.data ?? null;
  let raw;
  if (productIdOverride) {
    raw = { ...(baseRaw || {}), product_id: productIdOverride };
  } else {
    raw = baseRaw;
  }

  const doc = {
    brand_id: brand,
    event_id: e.event_id,
    session_id: sessionId,
    actor_id: actorId,
    event_name: e.event_name,
    occurred_at: displayOccurredAt ?? when,
    url: e.url || null,
    referrer: e.referrer || null,
    user_agent: e.user_agent || null,
    client_id: e.client_id || null,
    visitor_id: e.visitor_id || null,
    session_start: timing?.session_start ?? null,
    session_end: timing?.session_end ?? null,
    session_time_spent: timing?.session_time_spent ?? null,
    raw
  };

  console.log('[event_insert]', JSON.stringify(doc, null, 2));
  return doc;
}

// ---------- Routes ----------
app.post('/collect', brandAuth, async (req, res) => {
  // ---------- Log incoming payload ----------
  try {
    const { body, headers } = req;
    const safeHeaders = { ...headers };

    if (safeHeaders['x-collector-key']) safeHeaders['x-collector-key'] = '[redacted]';
    if (safeHeaders['x-collector-keys']) safeHeaders['x-collector-keys'] = '[redacted]';

    console.log(
      '[collector] incoming event:',
      JSON.stringify(
        {
          brand: req.brand || getHeader(req, 'X-Brand'),
          headers: safeHeaders,
          body
        },
        null,
        2
      )
    );
  } catch {
    // ignore logging errors
  }
  // ---------------------------------------------------------------------------

  if (req.body?.event_name === 'click') {
    try {
      const e = ClickEventSchema.parse(req.body);

      const when = new Date(e.occurred_at);
      if (isNaN(when.getTime())) return res.sendStatus(400);

      const actorId = e.actor_id || e.client_id || null;
      const clickBucket = classifyClick(e.data.signals);

      const runInsert = async () => {
        const timing = await resolveSessionTiming(req.brand, actorId, when);
        const displayOccurredAt = toStoreLocalOccurredAt(when, req.brandCreds?.store_timezone_iana);

        const doc = {
          brand_id: req.brand,
          event_id: e.event_id,
          event_name: e.event_name,
          occurred_at: displayOccurredAt,
          ingested_at: new Date(),
          client_id: e.client_id || null,
          visitor_id: e.visitor_id || null,
          session_id: timing.session_id,
          actor_id: actorId,
          session_start: timing.session_start,
          session_end: timing.session_end,
          session_time_spent: timing.session_time_spent,
          url: e.url || null,
          referrer: e.referrer || null,
          user_agent: e.user_agent || null,
          click: e.data.click,
          signals: e.data.signals,
          click_bucket: clickBucket,
          raw: e
        };

        console.log('[click_event_insert]', JSON.stringify(doc, null, 2));

        const result = await ClickEvent.updateOne(
          { event_id: e.event_id },
          { $setOnInsert: doc },
          { upsert: true }
        );

        if (result.upsertedCount > 0) {
          await commitSessionCursor(req.brand, actorId, timing, when, { collection: 'click_events', event_id: e.event_id }, doc);
        }
      };

      // Serialize the read-decide-write cycle per actor to avoid races
      // between near-simultaneous events (see withActorLock above).
      if (actorId) {
        await withActorLock(`${req.brand}|${actorId}`, runInsert);
      } else {
        await runInsert();
      }

      return res.sendStatus(204);
    } catch (err) {
      console.error(err);
      return res.sendStatus(400);
    }
  }

  try {
    const normalized = {
      ...req.body,
      client_id: safe(req.body.client_id),
      visitor_id: safe(req.body.visitor_id),
      session_id: req.body.session_id ?? null,
      actor_id: safe(req.body.actor_id),
      url: safe(req.body.url),
      referrer: safe(req.body.referrer),
      user_agent: safe(req.body.user_agent)
    };
    // attach parsed slug info (kept minimal) so it's available in validation/result
    normalized.slug_info = parseShopifySlug(req.body.url);

    const e = EventSchema.parse(normalized);

    const when = new Date(e.occurred_at);
    if (isNaN(when.getTime())) return res.sendStatus(400);

    const isPV = e.event_name === 'page_viewed';

    // actor_id is a persistent, ~1-year cookie the pixel manages on its own
    // (see README for details) — trusted as-is, falling back to client_id.
    // session_id, however, is server-generated: resolveSessionTiming mints
    // a fresh one whenever a new session starts (per SESSION_TIMEOUT) and
    // reuses it while the actor keeps sending events within that window.
    const actorId = e.actor_id || e.client_id || null;

    const runInsert = async () => {
      const timing = await resolveSessionTiming(req.brand, actorId, when);
      const sessionId = timing.session_id;
      const displayOccurredAt = toStoreLocalOccurredAt(when, req.brandCreds?.store_timezone_iana);

      // If this is a page view and we parsed a slug, consult slug_cache and inject product_id
      try {
        if (isPV && e.slug_info) {
          const cacheId = `${req.brand}:${e.slug_info.type}:${e.slug_info.slug}`;
          const cacheDoc = await SlugCache.findById(cacheId).lean().catch(() => null);
          if (cacheDoc && cacheDoc.shopify_id) {
            e.data = e.data || {};
            e.data.product_id = normalizeShopifyId(cacheDoc.shopify_id) || e.data.product_id;
          }
        }
      } catch {
        // swallow slug_cache errors, do not affect pipeline
      }

      // --- ATC write path (requires session + product) ---
      let productId = normalizeShopifyId(e?.data?.product_id ?? null);
      // Treat fallback IDs as "not really resolved" and synthesize a deterministic ID instead
      if (!productId || isFallbackId(productId)) {
        productId = synthPid(req.brand, sessionId, e);
      }

      let result;
      let docRefEventId = e.event_id;
      let insertDoc;

      if (e.event_name === 'product_added_to_cart' && sessionId && productId) {
        insertDoc = buildInsertDoc(req.brand, e, sessionId, actorId, when, productId, timing, displayOccurredAt);

        result = await Event.updateOne(
          { brand_id: req.brand, session_id: sessionId, event_name: e.event_name, "raw.product_id": productId },
          { $setOnInsert: insertDoc },
          { upsert: true }
        );
      } else {
        // generic idempotent event write
        insertDoc = buildInsertDoc(req.brand, e, sessionId, actorId, when, null, timing, displayOccurredAt);

        result = await Event.updateOne(
          { event_id: e.event_id },
          { $setOnInsert: insertDoc },
          { upsert: true }
        );
      }

      if (result.upsertedCount > 0) {
        await commitSessionCursor(req.brand, actorId, timing, when, { collection: 'events', event_id: docRefEventId }, insertDoc);
      }
    };

    // Serialize the read-decide-write cycle per actor to avoid races
    // between near-simultaneous events (see withActorLock above).
    if (actorId) {
      await withActorLock(`${req.brand}|${actorId}`, runInsert);
    } else {
      await runInsert();
    }

    res.sendStatus(204);
  } catch (err) {
    console.error(err);
    res.sendStatus(400);
  }
});

// ---------- Metrics ----------
//
// DISABLED: both endpoints depended on the `sessions` collection, which we
// no longer write to (see note at the top of this file). Left here,
// commented out, in case session-count reporting needs to be rebuilt on
// top of the `events` collection (e.g. distinct session_id/actor_id
// aggregation) later.
//
// app.get('/metrics/sessions', brandAuth, async (req, res) => {
//   try {
//     const from = req.query.from ? new Date(req.query.from) : new Date(Date.now() - 24 * 60 * 60 * 1000);
//     const to   = req.query.to   ? new Date(req.query.to)   : new Date();
//     const count = await Session.countDocuments({ brand_id: req.brand, started_at: { $gte: from, $lt: to } });
//     res.json({ brand: req.brand, from, to, sessions: count });
//   } catch {
//     res.status(400).json({ error: 'bad range' });
//   }
// });
//
// app.get('/metrics/sessions/:timestamp', brandAuth, async (req, res) => {
//   try {
//     const { timestamp } = req.params;
//     const eventName = 'product_added_to_cart';
//
//     // Parse timestamp (supports both epoch and ISO)
//     let ts;
//     if (/^\d+$/.test(timestamp)) {
//       const n = Number(timestamp);
//       const ms = timestamp.length === 10 ? n * 1000 : n;
//       ts = new Date(ms);
//     } else {
//       ts = new Date(timestamp);
//     }
//     if (isNaN(ts.getTime())) {
//       return res.status(400).json({ error: 'invalid timestamp' });
//     }
//
//     // Optional ?to=<time> upper bound, defaults to now
//     const to = req.query.to ? new Date(req.query.to) : new Date();
//     if (isNaN(to.getTime())) {
//       return res.status(400).json({ error: 'invalid to timestamp' });
//     }
//
//     // Prepare both queries (but don't await yet)
//     const sessionsPromise = Session.countDocuments({
//       brand_id: req.brand,
//       started_at: { $gt: ts, $lte: to }
//     });
//
//     const atcSessionsPromise = Event.aggregate([
//       {
//         $match: {
//           brand_id: req.brand,
//           event_name: eventName,
//           occurred_at: { $gt: ts, $lte: to },
//           session_id: { $type: 'string' }
//         }
//       },
//       { $group: { _id: '$session_id' } },
//       { $count: 'unique_atc_sessions' }
//     ]);
//
//     // Run in parallel
//     const [totalSessions, atcAgg] = await Promise.all([sessionsPromise, atcSessionsPromise]);
//
//     const totalAtcSessions = atcAgg?.[0]?.unique_atc_sessions || 0;
//
//     res.json({
//       brand: req.brand,
//       from: ts,
//       to,
//       eventName,
//       totalSessions,
//       totalEvents: totalAtcSessions
//     });
//   } catch (e) {
//     console.error(e);
//     res.status(500).json({ error: 'internal' });
//   }
// });

app.get('/healthz', (_, res) => res.json({ ok: true }));

// ---------- Bootstrap ----------
(async () => {
  // Fail loudly on startup if brand credentials can't be loaded at all —
  // no brands loaded means no request could ever authenticate anyway.
  await refreshBrandCredentials();
  scheduleDailyBrandRefresh();

  await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    maxPoolSize: 10
  });
  try {
    // Note: syncIndexes() drops any index that exists on the collection but
    // isn't declared in the schema above. The events/click_events TTL index
    // is deliberately NOT declared here (added/managed manually instead) —
    // if it's created directly in MongoDB, that's fine, syncIndexes() won't
    // touch it as long as it stays undeclared in these schemas.
    // await Session.syncIndexes(); // disabled, see note above
    await Event.syncIndexes();
    await ClickEvent.syncIndexes();
    await ActorCursor.syncIndexes();
    await SessionHistory.syncIndexes();
  } catch (e) {
    console.warn('Index sync failed:', e?.message || e);
  }
  app.listen(PORT, () => console.log(`collector listening on :${PORT}`));
})();
