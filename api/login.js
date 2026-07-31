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

// Hash PIN salé : HMAC-SHA256(pin, secret_serveur) — non pré-calculable sans le secret
async function pinHmac(pin, login, secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret + '|pin|' + login),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(pin));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── TOTP (RFC 6238) : HMAC-SHA1, pas de 30 s, 6 chiffres ──
function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = String(s).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, val = 0; const out = [];
  for (const ch of s) {
    const idx = A.indexOf(ch);
    if (idx < 0) continue;
    val = (val << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

async function totpAt(secretBytes, counter) {
  const buf = new ArrayBuffer(8); const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 4294967296));
  dv.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const off = sig[sig.length - 1] & 0x0f;
  const bin = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
  return String(bin % 1000000).padStart(6, '0');
}

// Tolérance ±1 fenêtre (30 s) pour absorber la dérive d'horloge du téléphone
async function verifyTotp(secret, code) {
  const clean = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  const bytes = base32Decode(secret);
  if (!bytes.length) return false;
  const ctr = Math.floor(Date.now() / 30000);
  for (let w = -1; w <= 1; w++) {
    if (await totpAt(bytes, ctr + w) === clean) return true;
  }
  return false;
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

  // ── Rate limiting : verrouillage après 5 échecs, fenêtre 15 min ──
  const MAX_TRIES = 5, LOCK_MS = 15 * 60 * 1000;
  const nowTs = Date.now();
  async function readAttempts(l) {
    try {
      const r = await fetch(SB_URL + '/rest/v1/login_attempts?login=eq.' + encodeURIComponent(l) + '&select=*', {
        headers: { apikey: SRK, Authorization: 'Bearer ' + SRK }
      });
      if (r.ok) { const a = await r.json(); return a && a[0]; }
    } catch {}
    return null;
  }
  async function bumpAttempts(l, fail) {
    const cur = await readAttempts(l);
    const body2 = fail
      ? { login: l, fails: ((cur && cur.fails) || 0) + 1, last_fail: nowTs }
      : { login: l, fails: 0, last_fail: nowTs };
    try {
      await fetch(SB_URL + '/rest/v1/login_attempts', {
        method: 'POST',
        headers: { apikey: SRK, Authorization: 'Bearer ' + SRK, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates' },
        body: JSON.stringify(body2)
      });
    } catch {}
  }
  const att = await readAttempts(login);
  if (att && att.fails >= MAX_TRIES && (nowTs - (att.last_fail || 0)) < LOCK_MS) {
    const wait = Math.ceil((LOCK_MS - (nowTs - att.last_fail)) / 60000);
    return json({ error: 'Trop de tentatives. Réessayez dans ' + wait + ' min.' }, 429);
  }

  // ── Admin hardcodé ──
  if (login === ADMIN_LOGIN) {
    const h = await sha256hex(pin);
    if (h !== ADMIN_PIN_HASH) { await bumpAttempts(login, true); return json({ error: 'Identifiant ou code PIN incorrect' }, 401); }

    // ── 2e facteur (TOTP) ── actif uniquement si MEDIREPORT_TOTP_SECRET est défini.
    // Variable absente = MFA désactivé (procédure de secours en cas de perte du téléphone).
    const TOTP_SECRET = process.env.MEDIREPORT_TOTP_SECRET;
    if (TOTP_SECRET) {
      const code = String(body.totp || '').trim();
      // PIN correct mais code absent : on réclame le 2e facteur sans incrémenter le compteur
      if (!code) return json({ error: 'mfa_required' }, 401);
      const okTotp = await verifyTotp(TOTP_SECRET, code);
      if (!okTotp) { await bumpAttempts(login, true); return json({ error: 'Code à deux facteurs incorrect' }, 401); }
    }

    await bumpAttempts(login, false);
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
  if (!user) { await bumpAttempts(login, true); return json({ error: 'Identifiant ou code PIN incorrect' }, 401); }

  // Comparaison PIN : HMAC salé (nouveau) OU sha256 (ancien) OU clair (legacy) — migration douce
  const pinHmacVal = await pinHmac(pin, login, SRK);
  const pinSha = await sha256hex(pin);
  const stored = String(user.pin || '');
  const ok = stored === pinHmacVal || stored === pinSha || stored === pin;
  if (!ok) { await bumpAttempts(login, true); return json({ error: 'Identifiant ou code PIN incorrect' }, 401); }
  await bumpAttempts(login, false);

  // Ré-encodage transparent : si le PIN était en clair ou en SHA-256, on le migre en HMAC salé
  if (stored !== pinHmacVal) {
    try {
      await fetch(SB_URL + '/rest/v1/users?id=eq.' + encodeURIComponent(user.id), {
        method: 'PATCH',
        headers: { apikey: SRK, Authorization: 'Bearer ' + SRK, 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: pinHmacVal })
      });
    } catch {}
  }

  const { pin: _omit, ...safeUser } = user;
  safeUser.patientId = user.patient_id || null;
  const payload = { u: user.id, r: user.role, e: Date.now() + TOKEN_TTL_MS, sv: (user.session_version || 0) };
  if (user.role === 'patient' && user.patient_id) payload.p = user.patient_id;

  // ── Compte famille : dossiers liés (enfants) ──
  safeUser.linkedPatients = [];
  if (user.role === 'patient') {
    try {
      const lr = await fetch(SB_URL + '/rest/v1/patient_links?user_id=eq.' + encodeURIComponent(user.id)
        + '&actif=eq.true&select=patient_id,relation', {
        headers: { apikey: SRK, Authorization: 'Bearer ' + SRK }
      });
      if (lr.ok) {
        let links = await lr.json();
        if (Array.isArray(links) && links.length) {
          // Majorité = coupure automatique : on exclut les dossiers d'enfants devenus majeurs (>= 216 mois)
          try {
            const ids = links.map(l => l.patient_id);
            const pr = await fetch(SB_URL + '/rest/v1/patients?id=in.(' + ids.map(encodeURIComponent).join(',') + ')&select=id,dob', {
              headers: { apikey: SRK, Authorization: 'Bearer ' + SRK }
            });
            if (pr.ok) {
              const pats = await pr.json();
              const now = new Date();
              const minorIds = new Set(pats.filter(p => {
                const m = String(p.dob || '').match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
                if (!m) return true; // dob illisible : on garde (prudence, cas rare)
                const b = new Date(+m[3], +m[2] - 1, +m[1]);
                let months = (now.getFullYear() - b.getFullYear()) * 12 + (now.getMonth() - b.getMonth());
                if (now.getDate() < b.getDate()) months--;
                return months < 216;
              }).map(p => p.id));
              links = links.filter(l => minorIds.has(l.patient_id));
            }
          } catch { /* en cas d'échec du filtre, on ne coupe pas (les liens restent) */ }
          if (links.length) {
            payload.pl = links.map(l => l.patient_id);
            safeUser.linkedPatients = links;
          }
        }
      }
    } catch { /* table absente ou indisponible : mode mono-dossier */ }
  }

  const token = await signToken(payload, SRK);
  return json({ token, user: safeUser });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
