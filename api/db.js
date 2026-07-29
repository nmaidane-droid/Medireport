export const config = { runtime: 'edge' };

const SB_URL = 'https://sfpjcqhaunkicllzvoba.supabase.co';

// Tables autorisées via le proxy
const TABLES = new Set([
  'users', 'patients', 'patient_access', 'consultations', 'labos', 'prescriptions',
  'imagerie', 'rdv', 'demandes_labo', 'demandes_avis', 'demandes_acces',
  'seen_items', 'notifications_vues', 'backups', 'vaccins', 'patient_links'
]);

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function verifyToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key, b64urlToBytes(sig), new TextEncoder().encode(data));
  if (!valid) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(data)));
    if (!payload.e || Date.now() > payload.e) return null; // expiré
    return payload; // { u: userId, r: role, e: expiry }
  } catch { return null; }
}

export default async function handler(req) {
  if (req.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  const SRK = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SRK) return json({ error: 'Server not configured' }, 500);

  // ── Authentification ──
  const session = await verifyToken(req.headers.get('x-session'), SRK);
  if (!session) return json({ error: 'Session invalide ou expirée' }, 401);

  let body;
  try { body = await req.json(); } catch { return json({ error: 'Bad request' }, 400); }

  const path = String(body.path || '');
  const method = String(body.method || 'GET').toUpperCase();
  const table = path.split('?')[0].split('/')[0];

  if (!TABLES.has(table)) return json({ error: 'Table non autorisée' }, 403);
  if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) return json({ error: 'Méthode non autorisée' }, 403);

  const role = session.r;
  let effectivePath = path;

  // ── Règles d'accès par rôle ──
  // Patients (accès mobile) : lecture seule + marquage vu, STRICTEMENT limité à leur propre dossier
  if (role === 'patient') {
    const allowedWrite = (table === 'seen_items' || table === 'notifications_vues');
    if (method !== 'GET' && !allowedWrite) return json({ error: 'Accès refusé' }, 403);
    if (table === 'backups') return json({ error: 'Accès refusé' }, 403);

    const myPatientId = session.p;
    const myUserId = session.u;
    // Compte famille : dossiers autorisés = le sien + les dossiers liés (pl, signés dans le token)
    const allowedPids = [myPatientId, ...(Array.isArray(session.pl) ? session.pl : [])].filter(Boolean);
    const sep = effectivePath.includes('?') ? '&' : '?';
    const PATIENT_SCOPED = ['consultations', 'labos', 'prescriptions', 'imagerie', 'rdv',
                            'patient_access', 'demandes_labo', 'demandes_avis', 'demandes_acces', 'vaccins'];
    if (PATIENT_SCOPED.includes(table)) {
      if (!allowedPids.length) return json({ error: 'Accès refusé' }, 403);
      // Si le client demande un dossier précis, il doit être autorisé ; sinon on force le sien
      const m = effectivePath.match(/[?&]patient_id=eq\.([^&]+)/);
      if (m) {
        if (!allowedPids.includes(decodeURIComponent(m[1]))) return json({ error: 'Accès refusé' }, 403);
        // filtre déjà présent et légitime — on le laisse
      } else {
        effectivePath = effectivePath + sep + 'patient_id=eq.' + encodeURIComponent(myPatientId);
      }
    } else if (table === 'patients') {
      if (!allowedPids.length) return json({ error: 'Accès refusé' }, 403);
      const m = effectivePath.match(/[?&]id=eq\.([^&]+)/);
      if (m) {
        if (!allowedPids.includes(decodeURIComponent(m[1]))) return json({ error: 'Accès refusé' }, 403);
      } else {
        // Sans filtre : renvoyer tous les dossiers autorisés (soi + enfants)
        effectivePath = effectivePath + sep + 'id=in.(' + allowedPids.map(encodeURIComponent).join(',') + ')';
      }
    } else if (table === 'patient_links') {
      // Lecture seule de SES propres liens
      if (method !== 'GET') return json({ error: 'Accès refusé' }, 403);
      effectivePath = 'patient_links?select=patient_id,relation,actif&user_id=eq.' + encodeURIComponent(myUserId) + '&actif=eq.true';
    } else if (table === 'users') {
      // Annuaire des professionnels : colonnes publiques UNIQUEMENT (select forcé,
      // le client ne peut pas demander pin/login/patient_id)
      effectivePath = 'users?select=id,prenom,nom,titre,spec,structure,role,color,initials';
    } else if (table === 'seen_items' || table === 'notifications_vues') {
      if (method === 'GET') effectivePath = effectivePath + sep + 'user_id=eq.' + encodeURIComponent(myUserId);
    }
  }
  // Table backups : admin uniquement
  if (table === 'backups' && role !== 'admin') return json({ error: 'Accès refusé' }, 403);
  // Vaccins : écriture réservée aux soignants et à l'admin
  if (table === 'vaccins' && method !== 'GET' && !['admin', 'medecin', 'specialiste'].includes(role))
    return json({ error: 'Accès refusé' }, 403);
  // Liens famille : gestion par soignants/admin (le patient ne peut que lire les siens)
  if (table === 'patient_links' && method !== 'GET' && !['admin', 'medecin', 'specialiste'].includes(role))
    return json({ error: 'Accès refusé' }, 403);
  // Écriture/suppression sur users : création autorisée aux pros (activation mobile), modification/suppression admin
  if (table === 'users') {
    if ((method === 'PATCH' || method === 'DELETE') && role !== 'admin')
      return json({ error: 'Accès refusé' }, 403);
    if (method === 'POST' && !['admin', 'medecin', 'specialiste'].includes(role))
      return json({ error: 'Accès refusé' }, 403);
  }

  // ── Relais vers Supabase avec la clé service_role ──
  const headers = {
    apikey: SRK,
    Authorization: 'Bearer ' + SRK,
    'Content-Type': 'application/json'
  };
  if (body.prefer) headers.Prefer = body.prefer;
  else if (method !== 'GET') headers.Prefer = 'return=representation';

  const res = await fetch(SB_URL + '/rest/v1/' + effectivePath, {
    method,
    headers,
    body: method === 'GET' ? undefined : (body.body ?? undefined)
  });

  const text = await res.text();

  // ── Filtrage : masquer les PINs sauf pour l'admin ──
  if (table === 'users' && method === 'GET' && role !== 'admin' && text) {
    try {
      const rows = JSON.parse(text);
      const cleaned = Array.isArray(rows) ? rows.map(({ pin, ...rest }) => rest) : rows;
      return json(cleaned, res.status);
    } catch { /* passe tel quel si non-JSON */ }
  }

  return new Response(text || 'null', {
    status: res.status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
