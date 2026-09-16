import mongoose from 'mongoose';

const clickSchema = new mongoose.Schema({
  x: { type: Number, default: null },
  y: { type: Number, default: null },
  tag_name: { type: String, default: null },
  element_id: { type: String, default: null },
  element_name: { type: String, default: null },
  element_type: { type: String, default: null },
  element_value: { type: String, default: null },
  href: { type: String, default: null }
}, { _id: false });

const signalsSchema = new mongoose.Schema({
  url_changed: { type: Boolean, required: true, default: false },
  cart_changed: { type: Boolean, required: true, default: false },
  ui_changed: { type: Boolean, required: true, default: false },
  meaningful_scroll: { type: Boolean, required: true, default: false }
}, { _id: false });

const clickEventSchema = new mongoose.Schema({
  brand_id: { type: String, required: true, index: true },
  event_id: { type: String, required: true },
  event_name: { type: String, required: true, default: 'click' },

  occurred_at: { type: Date, required: true },
  ingested_at: { type: Date, required: true, default: Date.now },

  client_id: { type: String, default: null, index: true },
  visitor_id: { type: String, default: null, index: true },
  session_id: { type: String, default: null, index: true },
  actor_id: { type: String, default: null, index: true },

  url: { type: String, default: null },
  referrer: { type: String, default: null },
  user_agent: { type: String, default: null },

  click: { type: clickSchema, required: true },
  signals: { type: signalsSchema, required: true },

  click_bucket: { type: String, required: true, enum: ['useful_click', 'dead_click'], index: true },

  raw: { type: mongoose.Schema.Types.Mixed }
}, { versionKey: false, collection: 'click_events' });

clickEventSchema.index(
  { event_id: 1 },
  { unique: true, partialFilterExpression: { event_id: { $type: 'string' } } }
);
clickEventSchema.index({ occurred_at: 1 }, { expireAfterSeconds: 2700 }); // TTL 45m
clickEventSchema.index({ brand_id: 1, occurred_at: 1 });
clickEventSchema.index({ session_id: 1, occurred_at: 1 });
clickEventSchema.index({ client_id: 1, occurred_at: 1 });
clickEventSchema.index({ brand_id: 1, actor_id: 1, occurred_at: 1 });
clickEventSchema.index({ click_bucket: 1, occurred_at: 1 });

export default mongoose.models.ClickEvent || mongoose.model('ClickEvent', clickEventSchema);
