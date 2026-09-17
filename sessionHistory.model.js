import mongoose from 'mongoose';

// A permanent historical record, one document per COMPLETED session —
// inserted the moment a session closes (i.e. when a later event reveals the
// actor's previous session timed out). Unlike actor_cursors (a live pointer
// that gets overwritten per-actor), this collection is append-only: every
// session an actor ever completes gets its own permanent snapshot here,
// including the events_seq that would otherwise be lost once actor_cursors
// moves on to the next session.
const sessionHistorySchema = new mongoose.Schema({
  brand_id: { type: String, required: true, index: true },
  actor_id: { type: String, required: true, index: true },
  session_id: { type: String, required: true, index: true },

  session_start: { type: Date, required: true },
  session_end: { type: Date, required: true },
  session_time_spent: { type: Number, required: true }, // milliseconds

  // session_end converted to the store's local timezone for display —
  // mirrors how individual events' occurred_at field works. session_end
  // itself stays true UTC for correctness (session-gap math, ordering).
  occurred_at: { type: Date, required: true },

  events_seq: { type: mongoose.Schema.Types.Mixed, default: {} },

  last_ref: {
    collection: { type: String, required: true, enum: ['events', 'click_events'] },
    event_id: { type: String, required: true }
  }
}, { versionKey: false, collection: 'session_history', timestamps: true });

sessionHistorySchema.index({ brand_id: 1, actor_id: 1, session_start: -1 });

export default mongoose.models.SessionHistory || mongoose.model('SessionHistory', sessionHistorySchema);
