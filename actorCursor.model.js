import mongoose from 'mongoose';

// A tiny, single-document-per-actor pointer used only to decide session
// boundaries (session_start/session_end/session_time_spent) across the
// events and click_events collections. NOT a return of the old `sessions`
// collection — no landing page, UTM, etc. Just enough state to know "when
// did this actor's current session start" and "which document was their
// most recent event", so it can be patched with session_end/session_time_spent
// once a later event reveals the session has closed.
const actorCursorSchema = new mongoose.Schema({
  brand_id: { type: String, required: true },
  actor_id: { type: String, required: true },

  session_start: { type: Date, required: true },
  last_event_at: { type: Date, required: true },

  last_ref: {
    collection: { type: String, required: true, enum: ['events', 'click_events'] },
    event_id: { type: String, required: true }
  }
}, { versionKey: false, collection: 'actor_cursors', timestamps: true });

actorCursorSchema.index({ brand_id: 1, actor_id: 1 }, { unique: true });

export default mongoose.models.ActorCursor || mongoose.model('ActorCursor', actorCursorSchema);
