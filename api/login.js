export const config = { runtime: 'edge' };

const ADMIN_LOGIN = 'admin';
const ADMIN_PIN_HASH = 'c27930584abbf709a1858e7e75ec8e0e579cffd2d56c36142f15190a4df3a4c2';
const ADMIN_USER = { id: 'u_admin', prenom: 'Administrateur', nom: '', role: 'admin', login: 'admin', initials: 'AD', color: '#1A6EFF' };
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12h

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signToken(payload, secret) {
  const data = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return data + '.' + b64url(sig);
}

export default async function handler(req) {
  if (req.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  const SB_URL = 'https://sfpjcqhaunkicllzvoba.supabase.co';
  const SRK = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SRK) return json({ error: 'Server not configured' }, 500);

  let body;
  try { body = await req.json(); } catch { return json({ error: 'Bad request' }, 400); }
  const login = (body.login || '').trim().toLowerCase();
  const pin = (body.pin || '').trim();
  if (!login || !pin) return json({ error: 'Identifiant ou PIN manquant' }, 400);

  // ── Admin hardcodé ──
  if (login === ADMIN_LOGIN) {
    const h = await sha256hex(pin);
    if (h !== ADMIN_PIN_HASH) return json({ error: 'Code PIN incorrect' }, 401);
    const token = await signToken({ u: ADMIN_USER.id, r: 'admin', e: Date.now() + TOKEN_TTL_MS }, SRK);
    return json({ token, user: ADMIN_USER });
  }

  // ── Utilisateurs Supabase ──
  const res = await fetch(SB_URL + '/rest/v1/users?login=eq.' + encodeURIComponent(login) + '&select=*', {
    headers: { apikey: SRK, Authorization: 'Bearer ' + SRK }
  });
  if (!res.ok) return json({ error: 'Service indisponible' }, 502);
  const rows = await res.json();
  const user = rows && rows[0];
  if (!user) return json({ error: 'Identifiant inconnu' }, 401);

  // Comparaison PIN : accepte en clair (transition) ou hashé SHA-256
  const pinHash = await sha256hex(pin);
  const stored = String(user.pin || '');
  const ok = stored === pin || stored === pinHash;
  if (!ok) return json({ error: 'Code PIN incorrect' }, 401);

  const { pin: _omit, ...safeUser } = user;
  safeUser.patientId = user.patient_id || null;
  const payload = { u: user.id, r: user.role, e: Date.now() + TOKEN_TTL_MS };
  if (user.role === 'patient' && user.patient_id) payload.p = user.patient_id;
  const token = await signToken(payload, SRK);
  return json({ token, user: safeUser });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
