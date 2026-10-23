
import express from 'express';
import helmet from 'helmet';
import { google } from 'googleapis';
import crypto from 'node:crypto';

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '16kb' }));
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 3000);

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

const BASE_URL = required('BASE_URL').replace(/\/$/, '');
const DISCORD_CLIENT_ID = required('DISCORD_CLIENT_ID');
const DISCORD_CLIENT_SECRET = required('DISCORD_CLIENT_SECRET');
const GOOGLE_SHEET_ID = required('GOOGLE_SHEET_ID');
const GOOGLE_SERVICE_ACCOUNT_JSON = required('GOOGLE_SERVICE_ACCOUNT_JSON');
const SHEET_RANGE = process.env.SHEET_RANGE || 'ชีต1!D2:D';

const SESSION_TTL_MS = 10 * 60 * 1000;
const sessions = new Map();
const states = new Map();

function timingSafeEqualString(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));

  return aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb);
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

  if (!timingSafeEqualString(getBearer(req), session.secret)) {
    return null;
  }

  return session;
}

function oauthUrl(state) {
  const url = new URL('https://discord.com/oauth2/authorize');

  url.searchParams.set('client_id', DISCORD_CLIENT_ID);
  url.searchParams.set(
    'redirect_uri',
    `${BASE_URL}/auth/discord/callback`
  );
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'identify');
  url.searchParams.set('state', state);

  return url.toString();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[c]);
}

function page(title, message) {
  return `<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
</head>
<body style="margin:0;background:#111;color:#f5f1e9;font:16px Segoe UI,sans-serif;display:grid;place-items:center;min-height:100vh">
<main style="max-width:560px;margin:24px;padding:32px;background:#202024;border:1px solid #d8b57a66;border-radius:16px;text-align:center">
<h1>${escapeHtml(title)}</h1>
<p>${message}</p>
<p style="color:#bdb9b2">คุณสามารถปิดหน้านี้และกลับไปที่ HSHONAD Launcher ได้</p>
</main>
</body>
</html>`;
}

// Google Sheets
let serviceAccount;

try {
  serviceAccount = JSON.parse(GOOGLE_SERVICE_ACCOUNT_JSON);
} catch {
  throw new Error(
    'GOOGLE_SERVICE_ACCOUNT_JSON is invalid JSON. Check Render Environment.'
  );
}

const auth = new google.auth.GoogleAuth({
  credentials: serviceAccount,
  scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly']
});

const sheets = google.sheets({
  version: 'v4',
  auth
});

async function isWhitelisted(discordId) {
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: GOOGLE_SHEET_ID,
    range: SHEET_RANGE,
    majorDimension: 'ROWS'
  });

  const rows = result.data.values || [];

  return rows.some(row =>
    String(row?.[0] ?? '').trim() === String(discordId)
  );
}

// Health check
app.get('/health', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ ok: true });
});

// Create login session
app.post('/api/launcher/device-sessions', (_req, res) => {
  const now = Date.now();

  for (const [id, session] of sessions) {
    if (session.expiresAt < now) {
      sessions.delete(id);
    }
  }

  for (const [state, id] of states) {
    if (!sessions.has(id)) {
      states.delete(state);
    }
  }

  const id = crypto.randomUUID();
  const secret = crypto.randomBytes(32).toString('base64url');
  const state = crypto.randomBytes(32).toString('base64url');

  sessions.set(id, {
    id,
    secret,
    state,
    status: 'pending',
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS
  });

  states.set(state, id);

  res.set('Cache-Control', 'no-store');

  res.json({
    device_session_id: id,
    device_secret: secret,
    verification_url: oauthUrl(state),
    expires_in: SESSION_TTL_MS / 1000
  });
});

// Discord OAuth callback
app.get('/auth/discord/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(
      page(
        'ยกเลิกการเข้าสู่ระบบ',
        'คุณยกเลิกการอนุญาต Discord แล้ว กลับไปที่ Launcher เพื่อเริ่มใหม่ได้'
      )
    );
  }

  if (typeof code !== 'string' || typeof state !== 'string') {
    return res.status(400).send(
      page(
        'เข้าสู่ระบบไม่สำเร็จ',
        'ข้อมูล OAuth ไม่ครบ กรุณาเริ่ม Login ใหม่จาก Launcher'
      )
    );
  }

  // Consume state once to prevent callback replay
  const id = states.get(state);
  const session = id ? sessions.get(id) : null;
  states.delete(state);

  if (
    !session ||
    session.expiresAt < Date.now() ||
    session.status !== 'pending' ||
    session.state !== state
  ) {
    return res.status(400).send(
      page(
        'เซสชันหมดอายุ',
        'กรุณากลับไปที่ Launcher แล้วเริ่ม Login ใหม่'
      )
    );
  }

  try {
    // Exchange OAuth code once
    const tokenResponse = await fetch(
      'https://discord.com/api/oauth2/token',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: 'authorization_code',
          code,
          redirect_uri: `${BASE_URL}/auth/discord/callback`
        }),
        signal: AbortSignal.timeout(15000)
      }
    );

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.json().catch(() => ({}));
      const retryHeader = tokenResponse.headers.get('retry-after');

      const retryHeaderNumber = retryHeader === null
        ? NaN
        : Number(retryHeader);

      const bodyRetryNumber = Number(errorData.retry_after);

      const retrySeconds = Number.isFinite(retryHeaderNumber)
        ? retryHeaderNumber
        : (
            Number.isFinite(bodyRetryNumber) && bodyRetryNumber >= 0
              ? bodyRetryNumber
              : null
          );

      // Log diagnostics only; never log OAuth code or credentials
      console.error('Discord token exchange failed:', {
        status: tokenResponse.status,
        retryAfterSeconds: retrySeconds,
        global: errorData.global ?? null,
        error: errorData.error || 'unknown_error',
        errorDescription:
          errorData.error_description || errorData.message || 'No description'
      });

      session.status = 'error';
      session.completedAt = Date.now();

      if (tokenResponse.status === 429) {
        const waitMessage = retrySeconds !== null
          ? `กรุณารอประมาณ ${Math.ceil(retrySeconds)} วินาที แล้วเริ่ม Login ใหม่`
          : 'Discord ยังจำกัดคำขอ กรุณารอสักครู่แล้วเริ่ม Login ใหม่';

        return res.status(429).send(
          page('Discord จำกัดคำขอชั่วคราว', waitMessage)
        );
      }

      return res.status(502).send(
        page(
          'เข้าสู่ระบบ Discord ไม่สำเร็จ',
          'ไม่สามารถยืนยันกับ Discord ได้ กรุณาตรวจ Render Logs และลองใหม่ภายหลัง'
        )
      );
    }

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error('Discord token response has no access_token');
    }

    // Get current Discord identity
    const userResponse = await fetch(
      'https://discord.com/api/users/@me',
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`
        },
        signal: AbortSignal.timeout(15000)
      }
    );

    if (!userResponse.ok) {
      console.error('Discord identity lookup failed:', {
        status: userResponse.status
      });

      throw new Error(
        `Discord identity lookup failed (${userResponse.status})`
      );
    }

    const user = await userResponse.json();

    if (!user.id || !user.username) {
      throw new Error('Discord did not return a valid user');
    }

    // Check the user's Discord ID against Google Sheets column D
    let allowed;

    try {
      allowed = await isWhitelisted(user.id);
    } catch (err) {
      console.error('Google Sheets whitelist check failed:', {
        message: String(err?.message || 'Unknown Sheets error'),
        status: err?.response?.status || null,
        code: err?.code || null
      });

      throw new Error('Google Sheets whitelist check failed');
    }

    session.username = user.global_name || user.username;
    session.discord_user_id = user.id;
    session.avatar_url = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`
      : '';

    session.status = allowed ? 'approved' : 'denied';
    session.completedAt = Date.now();

    if (allowed) {
      return res.send(
        page(
          'ตรวจสอบสำเร็จ',
          `ยืนยัน Discord สำเร็จแล้ว (${escapeHtml(session.username)}) กลับไปที่ HSHONAD Launcher ได้เลย`
        )
      );
    }

    return res.send(
      page(
        'ไม่ผ่าน Whitelist',
        'บัญชี Discord นี้ไม่มีอยู่ใน Whitelist กรุณาติดต่อผู้ดูแลเซิร์ฟเวอร์'
      )
    );
  } catch (err) {
    console.error('OAuth callback error:', {
      message: String(err?.message || 'Unknown OAuth error')
    });

    session.status = 'error';
    session.completedAt = Date.now();

    return res.status(500).send(
      page(
        'เกิดข้อผิดพลาด',
        'ตรวจสอบ Discord หรือ Google Sheets ไม่สำเร็จ กรุณาตรวจ Render Logs'
      )
    );
  }
});

// Launcher polls login status
app.get('/api/launcher/device-sessions/:id', (req, res) => {
  const session = findSession(req);

  if (!session) {
    return res.status(401).json({
      error: 'invalid_or_expired_session'
    });
  }

  res.set('Cache-Control', 'no-store');

  const body = {
    status: session.status
  };

  if (session.status === 'approved' || session.status === 'denied') {
    body.username = session.username || 'Discord User';
    body.discord_user_id = session.discord_user_id || '';
    body.avatar_url = session.avatar_url || '';
  }

  return res.json(body);
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'not_found' });
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled server error:', {
    message: String(err?.message || 'Unknown server error')
  });

  res.status(500).json({ error: 'internal_server_error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`HSHONAD auth backend listening on ${PORT}`);
});
