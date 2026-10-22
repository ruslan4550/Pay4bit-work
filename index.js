/**
 * YevroLato – Pay4bit backend (Cloudflare Workers)
 * Endpointlər:
 *   GET  /rate                    -> AZN/EUR aktiv məzənnə
 *   POST /create-payment          -> (Firebase token) Pay4bit linki yaradır
 *   GET  /payment-status?order=ID -> (Firebase token) sifariş statusu
 *   GET|POST /pay4bit/callback    -> Pay4bit CHECK / PAY / ERROR
 *   GET  /health
 * Secret key yalnız Cloudflare Secrets-də qalır.
 */

const PAY4BIT_URL = 'https://api.pay4bit.net/pay';
const CHARGE_CURRENCY = 'EUR';
const MIN_AZN = { card: 3, google: 3, apple: 3 };
const MAX_AZN = 2000;
const MIN_CHARGE = 1;
const RATE_TTL = 30 * 60 * 1000;

// ---------- Ümumi köməkçilər ----------
const enc = new TextEncoder();
const b64urlToBytes = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
};
const bytesToB64url = (buf) => {
  let s = ''; new Uint8Array(buf).forEach(b => s += String.fromCharCode(b));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const md5 = async (s) => hex(await crypto.subtle.digest('MD5', enc.encode(s)));
function safeEq(a, b) {
  a = String(a || ''); b = String(b || '');
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

function corsHeaders(req, env) {
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const origin = req.headers.get('Origin') || '';
  const h = {
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin'
  };
  if (!allowed.length) h['Access-Control-Allow-Origin'] = '*';
  else if (allowed.includes(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}
const json = (data, status, cors) =>
  new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json', ...cors } });

// ---------- Google OAuth (service account) + Firestore REST ----------
let sa = null, saToken = { value: null, exp: 0 };
function getSA(env) { return sa || (sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT)); }

async function getAccessToken(env) {
  if (saToken.value && Date.now() < saToken.exp - 60000) return saToken.value;
  const c = getSA(env);
  const now = Math.floor(Date.now() / 1000);
  const header = bytesToB64url(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = bytesToB64url(enc.encode(JSON.stringify({
    iss: c.client_email, scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600
  })));
  const pem = c.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), ch => ch.charCodeAt(0)),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(`${header}.${claim}`));
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${header}.${claim}.${bytesToB64url(sig)}` })
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('Google token alınmadı');
  saToken = { value: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return saToken.value;
}

const fsBase = (env) => `https://firestore.googleapis.com/v1/projects/${getSA(env).project_id}/databases/(default)`;
const docName = (env, path) => `projects/${getSA(env).project_id}/databases/(default)/documents/${path}`;

function toValue(v) {
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  return { nullValue: null };
}
const toFields = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, toValue(v)]));
function fromFields(f) {
  const o = {};
  for (const [k, v] of Object.entries(f || {})) {
    o[k] = 'stringValue' in v ? v.stringValue
      : 'integerValue' in v ? Number(v.integerValue)
      : 'doubleValue' in v ? v.doubleValue
      : 'booleanValue' in v ? v.booleanValue
      : 'timestampValue' in v ? v.timestampValue : null;
  }
  return o;
}

async function fsFetch(env, url, body, method) {
  const token = await getAccessToken(env);
  const r = await fetch(url, {
    method: method || (body ? 'POST' : 'GET'),
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  if (r.status === 404) return null;
  const j = await r.json();
  if (!r.ok) throw new Error('Firestore: ' + JSON.stringify(j.error || j));
  return j;
}
async function getDocument(env, path, txn) {
  const q = txn ? `?transaction=${encodeURIComponent(txn)}` : '';
  const d = await fsFetch(env, `${fsBase(env)}/documents/${path}${q}`);
  return d ? fromFields(d.fields) : null;
}
const commit = (env, writes, transaction) =>
  fsFetch(env, `${fsBase(env)}/documents:commit`, { writes, ...(transaction ? { transaction } : {}) });

// ---------- Firebase ID token yoxlaması ----------
let jwks = { keys: null, at: 0 };
async function verifyFirebaseToken(token, env) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('bad token');
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  const pid = getSA(env).project_id;

  if (!jwks.keys || Date.now() - jwks.at > 3600000) {
    const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
    jwks = { keys: (await r.json()).keys, at: Date.now() };
  }
  const jwk = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk || header.alg !== 'RS256') throw new Error('bad key');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
  const now = Math.floor(Date.now() / 1000);
  if (!ok || payload.aud !== pid || payload.iss !== `https://securetoken.google.com/${pid}`
      || payload.exp < now || !payload.sub) throw new Error('invalid token');
  return { uid: payload.sub };
}
async function requireUser(req, env) {
  const h = req.headers.get('Authorization') || '';
  if (!h.startsWith('Bearer ')) return null;
  try { return await verifyFirebaseToken(h.slice(7), env); } catch (e) { return null; }
}

// ---------- Aktiv məzənnə ----------
let rateCache = { aznPerEur: null, at: 0, source: null };
function bakuDate(offsetDays) {
  const d = new Date(Date.now() - offsetDays * 86400000);
  const p = new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Baku', day: '2-digit', month: '2-digit', year: 'numeric' })
    .formatToParts(d).reduce((a, x) => (a[x.type] = x.value, a), {});
  return `${p.day}.${p.month}.${p.year}`;
}
async function fetchCbarEur() {
  for (let i = 0; i < 4; i++) {
    const r = await fetch(`https://www.cbar.az/currencies/${bakuDate(i)}.xml`);
    if (!r.ok) continue;
    const m = (await r.text()).match(/Code="EUR"[\s\S]*?<Nominal>([^<]+)<\/Nominal>[\s\S]*?<Value>([^<]+)<\/Value>/);
    if (m) { const v = parseFloat(m[2]) / (parseFloat(String(m[1]).replace(/\D/g, '')) || 1); if (v > 0) return v; }
  }
  throw new Error('CBAR yoxdur');
}
async function fetchBackupEur() {
  const j = await (await fetch('https://open.er-api.com/v6/latest/EUR')).json();
  if (!(j && j.rates && j.rates.AZN > 0)) throw new Error('ehtiyat yoxdur');
  return j.rates.AZN;
}
async function getAznPerEur() {
  if (rateCache.aznPerEur && Date.now() - rateCache.at < RATE_TTL) return rateCache;
  try { rateCache = { aznPerEur: await fetchCbarEur(), at: Date.now(), source: 'CBAR' }; }
  catch (e1) {
    try { rateCache = { aznPerEur: await fetchBackupEur(), at: Date.now(), source: 'er-api' }; }
    catch (e2) { if (rateCache.aznPerEur) return rateCache; throw new Error('Məzənnə əldə edilə bilmədi'); }
  }
  return rateCache;
}
const aznToEur = (azn, rate, margin) =>
  (Math.ceil((azn / rate) * (1 + (Number(margin) || 0) / 100) * 100) / 100).toFixed(2);

// ---------- Handlers ----------
async function createPayment(req, env, cors) {
  const user = await requireUser(req, env);
  if (!user) return json({ success: false, error: 'Giriş tələb olunur' }, 401, cors);

  let body = {}; try { body = await req.json(); } catch (e) {}
  const method = String(body.method || '');
  if (!(method in MIN_AZN)) return json({ success: false, error: 'Yanlış ödəniş üsulu' }, 400, cors);

  const raw = String(body.amount ?? '').trim().replace(',', '.');
  if (!/^\d+(\.\d{1,2})?$/.test(raw)) return json({ success: false, error: 'Məbləğ yanlışdır' }, 400, cors);
  const azn = Number(raw);
  if (azn < MIN_AZN[method]) return json({ success: false, error: `Minimum ${MIN_AZN[method]} AZN` }, 400, cors);
  if (azn > MAX_AZN) return json({ success: false, error: `Maksimum ${MAX_AZN} AZN` }, 400, cors);

  const { aznPerEur, source } = await getAznPerEur();
  const amount = aznToEur(azn, aznPerEur, env.FX_MARGIN_PERCENT);
  if (Number(amount) < MIN_CHARGE) return json({ success: false, error: 'Məbləğ Pay4bit minimumundan (1 EUR) azdır' }, 400, cors);

  const orderId = Date.now().toString(36) + randHex(4);
  const desc = `YevroLato depozit ${orderId}`;
  const sign = await sha256(desc + orderId + amount + env.PAY4BIT_SECRET_KEY);

  await commit(env, [{
    update: {
      name: docName(env, `payments/${orderId}`),
      fields: toFields({ uid: user.uid, method, status: 'pending', aznAmount: azn, chargeAmount: amount,
        chargeCurrency: CHARGE_CURRENCY, aznPerEur, rateSource: source, desc, createdAt: new Date() })
    },
    currentDocument: { exists: false }
  }]);

  const params = { public_key: env.PAY4BIT_PUBLIC_KEY, account: orderId, sum: amount, currency: CHARGE_CURRENCY, desc, sign };
  const ps = { card: env.PAY4BIT_CARD_PS, google: env.PAY4BIT_GOOGLE_PS, apple: env.PAY4BIT_APPLE_PS }[method];
  if (ps) params.paySystem = ps;

  return json({ success: true, orderId, azn, charge: amount, currency: CHARGE_CURRENCY, aznPerEur,
    redirect_url: `${PAY4BIT_URL}?${new URLSearchParams(params)}` }, 200, cors);
}

async function paymentStatus(req, env, cors, url) {
  const user = await requireUser(req, env);
  if (!user) return json({ success: false, error: 'Giriş tələb olunur' }, 401, cors);
  const id = (url.searchParams.get('order') || '').replace(/[^a-z0-9]/gi, '');
  const d = id && await getDocument(env, `payments/${id}`);
  if (!d || d.uid !== user.uid) return json({ success: false }, 404, cors);
  return json({ success: true, status: d.status, azn: d.aznAmount }, 200, cors);
}

// params[x]=y formatını oxu (GET query və ya POST form/json)
async function readCallback(req, url) {
  let pairs = [...url.searchParams.entries()];
  let jsonBody = null;
  if (req.method === 'POST') {
    const ct = req.headers.get('Content-Type') || '';
    if (ct.includes('json')) { try { jsonBody = await req.json(); } catch (e) {} }
    else { try { pairs = pairs.concat([...new URLSearchParams(await req.text()).entries()]); } catch (e) {} }
  }
  const out = { method: '', params: {} };
  for (const [k, v] of pairs) {
    if (k === 'method') out.method = v;
    const m = k.match(/^params\[(.+)\]$/); if (m) out.params[m[1]] = v;
  }
  if (jsonBody) { out.method = jsonBody.method || out.method; Object.assign(out.params, jsonBody.params || {}); }
  out.method = String(out.method).toLowerCase();
  return out;
}

async function pay4bitCallback(req, env) {
  const url = new URL(req.url);
  const reply = (message, status) => json({ result: { message } }, status || 200, {});
  try {
    const { method, params: p } = await readCallback(req, url);
    const account = String(p.account || ''), amount = String(p.amount || ''), desc = String(p.desc || '');

    const okCheck = p.check_sign && safeEq(await sha256(desc + account + amount + env.PAY4BIT_SECRET_KEY), p.check_sign);
    const okSign = p.sign && p.localpayId &&
      safeEq(await md5(String(p.localpayId) + account + String(p.sum) + env.PAY4BIT_SECRET_KEY), p.sign);
    if (!okCheck && !okSign) return reply('Invalid signature', 400);

    const orderId = account.replace(/[^a-z0-9]/gi, '');
    const order = orderId && await getDocument(env, `payments/${orderId}`);
    if (!order) return reply('Order not found', 404);
    if (Number(amount).toFixed(2) !== order.chargeAmount || String(p.currency).toUpperCase() !== order.chargeCurrency)
      return reply('Amount mismatch', 400);

    if (method === 'check') return reply('Request successfully processed');

    if (method === 'error') {
      if (order.status === 'pending') await commit(env, [{
        update: { name: docName(env, `payments/${orderId}`), fields: toFields({ status: 'failed' }) },
        updateMask: { fieldPaths: ['status'] }
      }]);
      return reply('Request successfully processed');
    }

    if (method === 'pay') {
      const t = await fsFetch(env, `${fsBase(env)}/documents:beginTransaction`, { options: { readWrite: {} } });
      const txn = t.transaction;
      const cur = await getDocument(env, `payments/${orderId}`, txn);
      if (cur && cur.status === 'paid') {
        await fsFetch(env, `${fsBase(env)}/documents:rollback`, { transaction: txn });
        return reply('Request successfully processed');            // təkrar PAY – əlavə etmə
      }
      const azn = order.aznAmount;
      await commit(env, [
        { update: { name: docName(env, `payments/${orderId}`),
            fields: toFields({ status: 'paid', localpayId: String(p.localpayId || ''), paymentType: String(p.paymentType || '') }) },
          updateMask: { fieldPaths: ['status', 'localpayId', 'paymentType'] },
          updateTransforms: [{ fieldPath: 'paidAt', setToServerValue: 'REQUEST_TIME' }] },
        { update: { name: docName(env, `users/${order.uid}`) },
          updateMask: { fieldPaths: [] },
          updateTransforms: [
            { fieldPath: 'balance',       increment: { doubleValue: azn } },
            { fieldPath: 'points',        increment: { doubleValue: azn } },   // 1 AZN = 1 xal
            { fieldPath: 'payWheelSpins', increment: { integerValue: '1' } }
          ],
          currentDocument: { exists: true } },
        { update: { name: docName(env, `users/${order.uid}/history/${randHex(10)}`),
            fields: toFields({ type: 'deposit', amount: azn, description: `Pay4bit (${order.method}) depozit`, createdAt: new Date() }) } }
      ], txn);
      return reply('Request successfully processed');
    }
    return reply('Unknown method', 400);
  } catch (e) {
    console.error('[callback]', e && e.message);
    return reply('Server error', 500);
  }
}

// ---------- Router ----------
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = corsHeaders(req, env);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try {
      if (url.pathname === '/health') return json({ ok: true }, 200, cors);
      if (url.pathname === '/rate') {
        const r = await getAznPerEur();
        return json({ success: true, currency: CHARGE_CURRENCY, aznPerEur: r.aznPerEur, source: r.source }, 200, cors);
      }
      if (url.pathname === '/create-payment' && req.method === 'POST') return await createPayment(req, env, cors);
      if (url.pathname === '/payment-status') return await paymentStatus(req, env, cors, url);
      if (url.pathname === '/pay4bit/callback') return await pay4bitCallback(req, env);
      return json({ success: false, error: 'Not found' }, 404, cors);
    } catch (e) {
      console.error(e && e.message);
      return json({ success: false, error: 'Server xətası' }, 500, cors);
    }
  }
};
