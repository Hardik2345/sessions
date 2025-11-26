import mongoose from 'mongoose';

const slugCacheSchema = new mongoose.Schema({
  _id: { type: String, required: true }, // <brand>:<type>:<slug>
  brand: { type: String, required: true, index: true },
  type: { type: String, required: true, enum: ['product', 'collection'], index: true },
  slug: { type: String, required: true, index: true },
  shopify_id: { type: String, default: null },
  resolved_at: { type: Date, default: null }
}, { versionKey: false, collection: 'slug_cache' });

slugCacheSchema.index({ brand: 1, type: 1, slug: 1 }, { unique: true });

export default mongoose.models.SlugCache || mongoose.model('SlugCache', slugCacheSchema);
