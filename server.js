
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const { google } = require('googleapis');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || '').replace(/\/+$/, '');
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const GOOGLE_SHEET_ID = process.env.GOOGLE_SHEET_ID;
const SHEET_RANGE = process.env.SHEET_RANGE || 'ชีต1!D2:D';

const SESSION_TTL_MS = 10 * 60 * 1000;
const sessions = new Map();
const oauthStates = new Map();

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function htmlPage(title, message) {
  const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[c]);

  return `<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
body{font-family:Arial,sans-serif;background:#111827;color:#f9fafb;
display:grid;place-items:center;min-height:100vh;margin:0;padding:24px}
main{max-width:520px;background:#1f2937;padding:28px;border-radius:16px}
h1{font-size:24px}p{line-height:1.7;color:#d1d5db}
</style>
</head>
<body><main><h1>${escapeHtml(title)}</h1>
<p>${escapeHtml(message)}</p></main></body></html>`;
}

function checkConfig() {
  const missing = [];
  if (!BASE_URL) missing.push('BASE_URL');
  if (!DISCORD_CLIENT_ID) missing.push('DISCORD_CLIENT_ID');
  if (!DISCORD_CLIENT_SECRET) missing.push('DISCORD_CLIENT_SECRET');
  if (!GOOGLE_SHEET_ID) missing.push('GOOGLE_SHEET_ID');
  if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    missing.push('GOOGLE_SERVICE_ACCOUNT_JSON');
  }
  return missing;
}

function getRetryAfterSeconds(response, body) {
  // Discord ปกติส่ง Retry-After เป็นจำนวนวินาที
  const header = response.headers.get('retry-after');
  if (header !== null && header.trim() !== '') {
    const n = Number(header);
    if (Number.isFinite(n) && n >= 0) return n;

    // รองรับกรณี header เป็น HTTP-date
    const dateMs = Date.parse(header);
    if (Number.isFinite(dateMs)) {
      return Math.max(0, (dateMs - Date.now()) / 1000);
    }
  }

  const bodyValue = Number(body?.retry_after);
  if (body?.retry_after !== undefined &&
      Number.isFinite(bodyValue) && bodyValue >= 0) {
    return bodyValue;
  }

  return null;
}

function cleanExpiredData() {
  const now = Date.now();

  for (const [id, session] of sessions) {
    if (session.expiresAt <= now) {
      sessions.delete(id);
    }
  }

  for (const [state, item] of oauthStates) {
    if (item.expiresAt <= now) {
      oauthStates.delete(state);
    }
  }
}

function createSession() {
  const id = randomToken(24);
  const secret = randomToken(32);
  const state = randomToken(32);
  const now = Date.now();

  sessions.set(id, {
    id,
    secretHash: crypto.createHash('sha256').update(secret).digest('hex'),
    status: 'pending',
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    completedAt: null,
    discordUserId: null,
    errorCode: null
  });

  oauthStates.set(state, {
    sessionId: id,
    expiresAt: now + SESSION_TTL_MS
  });

  return { id, secret, state };
}

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (!/^[a-f0-9]+$/i.test(a) || !/^[a-f0-9]+$/i.test(b)) return false;

  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');

  return left.length === right.length &&
    left.length > 0 &&
    crypto.timingSafeEqual(left, right);
}

async function isDiscordUserWhitelisted(discordUserId) {
  let credentials;

  try {
    credentials = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  } catch {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON');
  }

  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly']
  });

  const sheets = google.sheets({ version: 'v4', auth });
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: GOOGLE_SHEET_ID,
    range: SHEET_RANGE
  });

  const rows = result.data.values || [];
  return rows.some((row) =>
    String(row?.[0] ?? '').trim() === String(discordUserId).trim()
  );
}

app.get('/health', (_req, res) => {
  const missing = checkConfig();

  res.status(missing.length ? 503 : 200).json({
    ok: missing.length === 0,
    service: 'hshonad-backend',
    missing
  });
});

app.post('/api/launcher/device-sessions', (_req, res) => {
  cleanExpiredData();

  const missing = checkConfig();
  if (missing.length) {
    return res.status(503).json({
      error: 'server_not_configured',
      message: 'Backend ยังตั้งค่าไม่ครบ',
      missing
    });
  }

  const { id, secret, state } = createSession();

  const verificationUrl =
    `${BASE_URL}/auth/discord?state=${encodeURIComponent(state)}`;

  return res.status(201).json({
    device_session_id: id,
    device_secret: secret,
    verification_url: verificationUrl,
    expires_in: Math.floor(SESSION_TTL_MS / 1000)
  });
});

app.get('/auth/discord', (req, res) => {
  cleanExpiredData();

  const state = String(req.query.state || '');
  const stateItem = oauthStates.get(state);

  if (!stateItem || stateItem.expiresAt <= Date.now()) {
    return res.status(400).send(htmlPage(
      'ลิงก์หมดอายุ',
      'กลับไปที่ Launcher แล้วเริ่ม Login ใหม่'
    ));
  }

  const redirectUri = `${BASE_URL}/auth/discord/callback`;
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: 'identify',
    state
  });

  return res.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`
  );
});

app.get('/auth/discord/callback', async (req, res) => {
  cleanExpiredData();

  const state = String(req.query.state || '');
  const stateItem = oauthStates.get(state);

  if (!stateItem || stateItem.expiresAt <= Date.now()) {
    return res.status(400).send(htmlPage(
      'คำขอหมดอายุ',
      'กลับไปที่ Launcher แล้วเริ่ม Login ใหม่'
    ));
  }

  // ใช้ state ได้ครั้งเดียว ป้องกัน callback เดิมถูกนำกลับมาใช้ซ้ำ
  oauthStates.delete(state);

  const session = sessions.get(stateItem.sessionId);
  if (!session || session.expiresAt <= Date.now()) {
    return res.status(400).send(htmlPage(
      'Session หมดอายุ',
      'กลับไปที่ Launcher แล้วเริ่ม Login ใหม่'
    ));
  }

  if (session.status !== 'pending') {
    return res.status(409).send(htmlPage(
      'คำขอนี้ถูกใช้แล้ว',
      'กลับไปตรวจสอบสถานะใน Launcher'
    ));
  }

  if (req.query.error) {
    session.status = 'denied';
    session.completedAt = Date.now();

    return res.status(400).send(htmlPage(
      'ยกเลิกการ Login',
      'คุณไม่ได้อนุญาตให้เชื่อมต่อ Discord กลับไปที่ Launcher ได้'
    ));
  }

  const code = String(req.query.code || '');
  if (!code) {
    session.status = 'error';
    session.errorCode = 'missing_code';
    session.completedAt = Date.now();

    return res.status(400).send(htmlPage(
      'Login ไม่สำเร็จ',
      'ไม่พบ OAuth code กรุณาเริ่ม Login ใหม่'
    ));
  }

  try {
    const redirectUri = `${BASE_URL}/auth/discord/callback`;
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
          redirect_uri: redirectUri
        })
      }
    );

    const tokenData = await tokenResponse.json().catch(() => ({}));

    if (!tokenResponse.ok) {
      const retryAfter = getRetryAfterSeconds(tokenResponse, tokenData);
      const scope = tokenResponse.headers.get('x-ratelimit-scope');
      const globalLimit = tokenResponse.headers.get('x-ratelimit-global');

      // ไม่บันทึก code, client secret, access token หรือ response ทั้งก้อน
      console.error('Discord token exchange failed:', {
        status: tokenResponse.status,
        retryAfterSeconds: retryAfter,
        scope,
        global: globalLimit,
        error: tokenData.error || tokenData.message || 'unknown_error'
      });

      session.status = 'error';
      session.errorCode = tokenResponse.status === 429
        ? 'discord_rate_limited'
        : 'discord_token_exchange_failed';
      session.completedAt = Date.now();

      if (tokenResponse.status === 429) {
        const waitMessage = retryAfter !== null
          ? `Discord แจ้งให้รอประมาณ ${Math.ceil(retryAfter)} วินาที ก่อนลองใหม่ อย่ากด Login ซ้ำระหว่างนี้`
          : 'Discord จำกัดคำขอชั่วคราว กรุณารอสักพักก่อนลองใหม่';

        return res.status(429).send(htmlPage(
          'Discord จำกัดคำขอชั่วคราว',
          waitMessage
        ));
      }

      return res.status(502).send(htmlPage(
        'แลกเปลี่ยน Token ไม่สำเร็จ',
        'Discord ปฏิเสธคำขอ กรุณาตรวจสอบ Client ID, Client Secret และ Redirect URI ใน Developer Portal กับ Render'
      ));
    }

    const accessToken = tokenData.access_token;
    if (!accessToken) {
      throw new Error('Discord response did not contain an access token');
    }

    const userResponse = await fetch(
      'https://discord.com/api/users/@me',
      {
        headers: { Authorization: `Bearer ${accessToken}` }
      }
    );

    if (!userResponse.ok) {
      console.error('Discord user lookup failed:', {
        status: userResponse.status
      });
      throw new Error('Discord user lookup failed');
    }

    const discordUser = await userResponse.json();

    if (!discordUser.id) {
      throw new Error('Discord user ID missing');
    }

    const allowed = await isDiscordUserWhitelisted(discordUser.id);

    session.status = allowed ? 'approved' : 'denied';
    session.discordUserId = discordUser.id;
    session.completedAt = Date.now();

    if (allowed) {
      return res.send(htmlPage(
        'Login สำเร็จ',
        'ตรวจสอบ Whitelist ผ่านแล้ว กลับไปที่ Launcher ได้เลย'
      ));
    }

    return res.status(403).send(htmlPage(
      'ไม่มีสิทธิ์เข้าใช้งาน',
      'ไม่พบ Discord User ID ของคุณใน Whitelist กรุณาติดต่อผู้ดูแลระบบ'
    ));
  } catch (error) {
    console.error('OAuth callback processing failed:', {
      message: error.message
    });

    session.status = 'error';
    session.errorCode = 'callback_processing_failed';
    session.completedAt = Date.now();

    return res.status(500).send(htmlPage(
      'เกิดข้อผิดพลาด',
      'ระบบตรวจสอบ Login ไม่สำเร็จ กรุณาตรวจสอบ Render Logs แล้วลองใหม่ภายหลัง'
    ));
  }
});

app.get('/api/launcher/device-sessions/:id', (req, res) => {
  cleanExpiredData();

  const session = sessions.get(String(req.params.id || ''));
  if (!session || session.expiresAt <= Date.now()) {
    return res.status(404).json({
      error: 'session_not_found',
      message: 'Session ไม่พบหรือหมดอายุแล้ว'
    });
  }

  const authHeader = String(req.get('authorization') || '');
  const match = authHeader.match(/^Bearer\s+([a-f0-9]+)$/i);

  if (!match) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const providedHash = crypto.createHash('sha256')
    .update(match[1])
    .digest('hex');

  if (!safeEqualHex(providedHash, session.secretHash)) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  return res.json({
    device_session_id: session.id,
    status: session.status,
    expires_in: Math.max(
      0,
      Math.floor((session.expiresAt - Date.now()) / 1000)
    )
  });
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'api_route_not_found' });
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled request error:', {
    message: err?.message || 'unknown_error'
  });

  if (res.headersSent) return;
  res.status(500).json({ error: 'internal_server_error' });
});

app.listen(PORT, () => {
  console.log(`Backend listening on port ${PORT}`);
});
