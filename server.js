// server.js
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
  origin: true, // or specify your domains: ['https://yourstore.com','https://checkout.shopify.com']
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Collector-Key'],
  maxAge: 86400
}));

app.options('/collect', cors());

const { MONGO_URI, PORT = 3000, COLLECTOR_KEY } = process.env;

// ---------- Mongo models ----------
const sessionSchema = new mongoose.Schema({
  session_id: { type: String, required: true, index: true, unique: true },
  actor_id:   { type: String, required: true, index: true }, // visitor_id (preferred) or client_id
  started_at: { type: Date,   required: true, index: true },
  last_event_at: { type: Date, required: true, index: true },
  landing_url: { type: String },
  landing_referrer: { type: String },
  // optional: attribution
  utm_source: String,
  utm_medium: String,
  utm_campaign: String,
  utm_term: String,
  utm_content: String
}, { versionKey: false, collection: 'sessions' });

// Fast lookups by actor and recency
sessionSchema.index({ actor_id: 1, last_event_at: -1 });

const eventSchema = new mongoose.Schema({
  event_id:   { type: String, required: true, unique: true },
  session_id: { type: String, index: true },
  event_name: { type: String, required: true, index: true },
  occurred_at:{ type: Date,   required: true, index: true },
  url:        { type: String },
  referrer:   { type: String },
  user_agent: { type: String },
  client_id:  { type: String, index: true },
  visitor_id: { type: String, index: true },
  raw:        { type: mongoose.Schema.Types.Mixed }
}, { versionKey: false, collection: 'events' });

// Useful compound index for time-series queries per session
eventSchema.index({ session_id: 1, occurred_at: 1 });

const Session = mongoose.model('Session', sessionSchema);
const Event   = mongoose.model('Event', eventSchema);

// ---------- Validation ----------
const EventSchema = z.object({
  event_id: z.string(),
  event_name: z.string(),
  occurred_at: z.string(), // ISO
  client_id: z.string().nullable(),
  visitor_id: z.string().nullable(),
  url: z.string().url().nullable(),
  referrer: z.string().nullable(),
  user_agent: z.string().nullable(),
  data: z.any().optional()
});

// ---------- Helpers ----------
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

function parseUTM(u) {
  try {
    if (!u) return {};
    const url = new URL(u);
    const get = k => url.searchParams.get(k) || undefined;
    return {
      utm_source:  get('utm_source'),
      utm_medium:  get('utm_medium'),
      utm_campaign:get('utm_campaign'),
      utm_term:    get('utm_term'),
      utm_content: get('utm_content')
    };
  } catch { return {}; }
}

// ---------- Routes ----------
app.post('/collect', async (req, res) => {
  console.log("Received event:", req.body);
  try {
    if (!COLLECTOR_KEY || req.get('X-Collector-Key') !== COLLECTOR_KEY) {
      return res.sendStatus(401);
    }

    const e = EventSchema.parse(req.body);
    const when = new Date(e.occurred_at);
    const actor = e.visitor_id || e.client_id; // prefer visitor_id, fallback to client_id

    // Create/update session (idempotent on time window)
    let sessionId = null;
    if (actor) {
      // find most recent session for this actor
      const recent = await Session.findOne({ actor_id: actor })
        .sort({ last_event_at: -1 })
        .lean();

      if (!recent || (when - new Date(recent.last_event_at)) > SESSION_TIMEOUT_MS) {
        // new session
        sessionId = uuid();
        const utm = parseUTM(e.url);
        await Session.create({
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
          { session_id: sessionId },
          { $set: { last_event_at: when } }
        );
      }
    }

    // store the event (ignore duplicates by event_id)
    await Event.updateOne(
      { event_id: e.event_id },
      {
        $setOnInsert: {
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

    return res.sendStatus(204);
  } catch (err) {
    console.error(err);
    return res.sendStatus(400);
  }
});

// Example: quick KPI — sessions count in a range
// GET /metrics/sessions?from=2025-08-01&to=2025-08-18
app.get('/metrics/sessions', async (req, res) => {
  try {
    const from = req.query.from ? new Date(req.query.from) : new Date(Date.now() - 24*60*60*1000);
    const to   = req.query.to   ? new Date(req.query.to)   : new Date();
    const count = await Session.countDocuments({ started_at: { $gte: from, $lt: to } });
    res.json({ from, to, sessions: count });
  } catch (e) {
    res.status(400).json({ error: 'bad range' });
  }
});

// Health
app.get('/healthz', (_, res) => res.json({ ok: true }));

// ---------- Bootstrap ----------
(async () => {
  await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    maxPoolSize: 10
  });
  app.listen(PORT, () => console.log(`collector on :${PORT}`));
})();
