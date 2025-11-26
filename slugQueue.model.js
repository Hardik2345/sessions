import mongoose from 'mongoose';

const slugQueueSchema = new mongoose.Schema({
  brand: { type: String, required: true, index: true },
  type: { type: String, required: true, enum: ['product', 'collection'], index: true },
  slug: { type: String, required: true, index: true },
  attempts: { type: Number, default: 0 },
  locked: { type: Boolean, default: false },
  queued_at: { type: Date, default: Date.now },
  locked_at: { type: Date, default: null },
  worker_id: { type: String, default: null },
  last_error: { type: String, default: null }
}, { versionKey: false, collection: 'slug_queue' });

slugQueueSchema.index({ brand: 1, type: 1, slug: 1 }, { unique: true });

export default mongoose.models.SlugQueue || mongoose.model('SlugQueue', slugQueueSchema);
