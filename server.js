import express from 'express';
import helmet from 'helmet';
import { google } from 'googleapis';
import crypto from 'node:crypto';

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '16kb' }));
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = required('BASE_URL').replace(/\/$/, '');
const DISCORD_CLIENT_ID = required('DISCORD_CLIENT_ID');
const DISCORD_CLIENT_SECRET = required('DISCORD_CLIENT_SECRET');
const GOOGLE_SHEET_ID = required('GOOGLE_SHEET_ID');
const GOOGLE_SERVICE_ACCOUNT_JSON = required('GOOGLE_SERVICE_ACCOUNT_JSON');
const SHEET_RANGE = process.env.SHEET_RANGE || "ชีต1!D2:D";
const SESSION_TTL_MS = 10 * 60 * 1000;
const sessions = new Map();
const states = new Map();

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function timingSafeEqualString(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function getBearer(req) {
  const header = req.get('authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7) : '';
}

function findSession(req) {
  const session = sessions.get(req.params.id);
  if (!session || session.expiresAt < Date.now()) {
    if (session) sessions.delete(req.params.id);
    return null;
  }
  if (!timingSafeEqualString(getBearer(req), session.secret)) return null;
  return session;
}

function oauthUrl(state) {
  const url = new URL('https://discord.com/oauth2/authorize');
  url.searchParams.set('client_id', DISCORD_CLIENT_ID);
  url.searchParams.set('redirect_uri', `${BASE_URL}/auth/discord/callback`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'identify');
  url.searchParams.set('state', state);
  return url.toString();
}

const serviceAccount = JSON.parse(GOOGLE_SERVICE_ACCOUNT_JSON);
const auth = new google.auth.GoogleAuth({
  credentials: serviceAccount,
  scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly']
});
const sheets = google.sheets({ version: 'v4', auth });

async function isWhitelisted(discordId) {
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: GOOGLE_SHEET_ID,
    range: SHEET_RANGE,
    majorDimension: 'ROWS'
  });
  const rows = result.data.values || [];
  return rows.some(row => String(row?.[0] ?? '').trim() === String(discordId));
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/api/launcher/device-sessions', (_req, res) => {
  // Expire old in-memory sessions on each new session request.
  for (const [id, session] of sessions) if (session.expiresAt < Date.now()) sessions.delete(id);
  for (const [state, id] of states) if (!sessions.has(id)) states.delete(state);

  const id = crypto.randomUUID();
  const secret = crypto.randomBytes(32).toString('base64url');
  const state = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  sessions.set(id, { id, secret, state, status: 'pending', createdAt: now, expiresAt: now + SESSION_TTL_MS });
  states.set(state, id);
  res.set('Cache-Control', 'no-store').json({
    device_session_id: id,
    device_secret: secret,
    verification_url: oauthUrl(state),
    expires_in: SESSION_TTL_MS / 1000
  });
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.status(400).send(page('ยกเลิกการเข้าสู่ระบบ', 'คุณยกเลิกการอนุญาต Discord แล้ว สามารถปิดหน้านี้และกลับไปที่ Launcher ได้'));
  if (typeof code !== 'string' || typeof state !== 'string') return res.status(400).send(page('เข้าสู่ระบบไม่สำเร็จ', 'ข้อมูล OAuth2 ไม่ครบ กรุณากลับไปลองใหม่ใน Launcher'));

  const id = states.get(state);
  const session = id ? sessions.get(id) : null;
  states.delete(state);
  if (!session || session.expiresAt < Date.now() || session.status !== 'pending' || session.state !== state) {
    return res.status(400).send(page('เซสชันหมดอายุ', 'กลับไปที่ Launcher แล้วเริ่ม Login ใหม่อีกครั้ง'));
  }

  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${BASE_URL}/auth/discord/callback`
      })
    });
    if (!tokenResponse.ok) throw new Error(`Discord token exchange failed (${tokenResponse.status})`);
    const tokenData = await tokenResponse.json();

    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    if (!userResponse.ok) throw new Error(`Discord identity lookup failed (${userResponse.status})`);
    const user = await userResponse.json();
    if (!user.id || !user.username) throw new Error('Discord did not return a valid user');

    // Verify the authenticated Discord ID against the existing sheet column D.
    const allowed = await isWhitelisted(user.id);
    session.username = user.global_name || user.username;
    session.discord_user_id = user.id;
    session.avatar_url = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`
      : '';
    session.status = allowed ? 'approved' : 'denied';
    session.completedAt = Date.now();

    return res.send(page(
      allowed ? 'ตรวจสอบสำเร็จ' : 'ไม่ผ่าน Whitelist',
      allowed
        ? `ยืนยัน Discord สำเร็จแล้ว (${escapeHtml(session.username)}) กลับไปที่ HSHONAD Launcher ได้เลย`
        : 'บัญชี Discord นี้ไม่มีอยู่ใน Whitelist กรุณาติดต่อผู้ดูแลเซิร์ฟเวอร์'
    ));
  } catch (err) {
    console.error('OAuth callback error:', err);
    session.status = 'error';
    return res.status(500).send(page('เกิดข้อผิดพลาด', 'ตรวจสอบ Discord หรือ Google Sheets ไม่สำเร็จ กรุณาลองใหม่ภายหลัง'));
  }
});

app.get('/api/launcher/device-sessions/:id', (req, res) => {
  const session = findSession(req);
  if (!session) return res.status(401).json({ error: 'invalid_or_expired_session' });
  res.set('Cache-Control', 'no-store');
  const body = { status: session.status };
  if (session.status === 'approved' || session.status === 'denied') {
    body.username = session.username || 'Discord User';
    body.discord_user_id = session.discord_user_id || '';
    body.avatar_url = session.avatar_url || '';
  }
  res.json(body);
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]);
}
function page(title, message) {
  return `<!doctype html><html lang="th"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><body style="margin:0;background:#111;color:#f5f1e9;font:16px Segoe UI,sans-serif;display:grid;place-items:center;min-height:100vh"><main style="max-width:560px;margin:24px;padding:32px;background:#202024;border:1px solid #d8b57a66;border-radius:16px;text-align:center"><h1>${escapeHtml(title)}</h1><p>${message}</p><p style="color:#bdb9b2">คุณสามารถปิดหน้านี้และกลับไปที่ Launcher ได้</p></main></body></html>`;
}

app.listen(PORT, '0.0.0.0', () => console.log(`HSHONAD auth backend listening on ${PORT}`));
