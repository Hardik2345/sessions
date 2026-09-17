import crypto from 'crypto';

const {
  GET_BRANDS_API,
  PIPELINE_KEY,
  PASSWORD_AES_KEY
} = process.env;

// AES-256-CBC needs exactly 32 raw key bytes. We don't know for certain
// whether PASSWORD_AES_KEY is base64 or a raw UTF-8 string, so try base64
// first and fall back to raw UTF-8 if that doesn't yield 32 bytes. The
// derived length (not the key itself) is logged once at startup so this can
// be verified against real data instead of silently assumed.
function deriveAesKey(raw) {
  if (!raw) return null;
  try {
    const b64 = Buffer.from(raw, 'base64');
    if (b64.length === 32) return b64;
  } catch {
    // fall through
  }
  const utf8 = Buffer.from(raw, 'utf8');
  return utf8;
}

const AES_KEY = deriveAesKey(PASSWORD_AES_KEY);
console.log('[brandCredentials] derived AES key length (bytes):', AES_KEY ? AES_KEY.length : 0, '(expected 32)');

function decryptAes256Cbc(encrypted, key) {
  const [ivB64, dataB64] = String(encrypted).split(':');
  const iv = Buffer.from(ivB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

function pipelineHeaders() {
  return { 'x-pipeline-key': PIPELINE_KEY };
}

// store_timezone looks like "(GMT+05:30) Asia/Kolkata" — pull out the IANA
// name so it can be passed straight to Intl.DateTimeFormat({ timeZone }).
function parseIanaTimezone(storeTimezone) {
  if (!storeTimezone) return null;
  const match = String(storeTimezone).match(/\)\s*(.+)$/);
  return match ? match[1].trim() : null;
}

let brandCredentialsCache = {}; // key: "<brand_tag>_shop" -> { intent_tracking_token, access_token, ... }

export function getBrandCredentials(brand) {
  return brandCredentialsCache[brand] || null;
}

export async function refreshBrandCredentials() {
  const listRes = await fetch(GET_BRANDS_API, { headers: pipelineHeaders() });
  if (!listRes.ok) {
    throw new Error(`GET_BRANDS_API list call failed: ${listRes.status}`);
  }
  const brandList = await listRes.json(); // { "1": "PTS", "2": "BBB", ... }

  const newCache = {};

  await Promise.all(
    Object.keys(brandList).map(async (brandId) => {
      try {
        const detailRes = await fetch(`${GET_BRANDS_API}/${brandId}`, { headers: pipelineHeaders() });
        if (!detailRes.ok) {
          console.error(`[brandCredentials] failed to fetch brand ${brandId}: ${detailRes.status}`);
          return;
        }
        const doc = await detailRes.json();

        if (!doc?.is_active || !doc?.intent_tracking_token) return;

        let accessToken = null;
        if (doc.access_token && AES_KEY) {
          try {
            accessToken = decryptAes256Cbc(doc.access_token, AES_KEY);
          } catch (err) {
            console.error(`[brandCredentials] failed to decrypt access_token for brand ${brandId}:`, err.message);
          }
        }

        const brandKey = `${doc.brand_tag}_shop`;
        newCache[brandKey] = {
          intent_tracking_token: doc.intent_tracking_token,
          access_token: accessToken,
          brand_id: doc.brand_id,
          brand_name: doc.brand_name,
          shop_name: doc.shop_name,
          store_timezone: doc.store_timezone || null,
          store_timezone_iana: parseIanaTimezone(doc.store_timezone)
        };
      } catch (err) {
        console.error(`[brandCredentials] error processing brand ${brandId}:`, err.message);
      }
    })
  );

  brandCredentialsCache = newCache;
  console.log('[brandCredentials] refreshed:', Object.keys(brandCredentialsCache).length, 'active brands loaded');
}
