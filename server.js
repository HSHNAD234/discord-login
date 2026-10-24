
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const { google } = require('googleapis');
const { Pool } = require('pg');

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
const LOGIN_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const sessions = new Map();
const oauthStates = new Map();
const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: /localhost|127\\.0\\.0\\.1/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
}) : null;
let schemaReady = false;

// Avoid creating more OAuth sessions while Discord has rate-limited the token endpoint.
let discordOAuthRateLimitedUntil = 0;

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function page(title, message) {
  const escapeHtml = (value) =>
    String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[char]);

  return `<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
body{font-family:Arial,sans-serif;background:#111827;color:#f9fafb;
display:grid;place-items:center;min-height:100vh;margin:0;padding:20px}
main{max-width:520px;background:#1f2937;padding:28px;border-radius:16px}
p{line-height:1.8;color:#d1d5db}
</style>
</head>
<body><main><h2>${escapeHtml(title)}</h2>
<p>${escapeHtml(message)}</p></main></body>
</html>`;
}

function missingConfig() {
  const required = [
    'BASE_URL',
    'DATABASE_URL',
    'DISCORD_CLIENT_ID',
    'DISCORD_CLIENT_SECRET',
    'GOOGLE_SHEET_ID',
    'GOOGLE_SERVICE_ACCOUNT_JSON'
  ];

  return required.filter((key) => !process.env[key]);
}

function cleanExpiredData() {
  const now = Date.now();

  for (const [id, session] of sessions) {
    if (session.expiresAt <= now) {
      sessions.delete(id);
    }
  }

  for (const [state, entry] of oauthStates) {
    if (entry.expiresAt <= now) {
      oauthStates.delete(state);
    }
  }
}

function requireDatabase(res) {
  if (!pool || !schemaReady) {
    res.status(503).json({ error: 'database_unavailable' });
    return false;
  }
  return true;
}

async function initializeSchema() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS launcher_login_sessions (
      token_hash TEXT PRIMARY KEY,
      discord_user_id TEXT NOT NULL,
      username TEXT,
      avatar_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      revoked_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS launcher_login_sessions_user_idx
      ON launcher_login_sessions (discord_user_id);
    CREATE INDEX IF NOT EXISTS launcher_login_sessions_expiry_idx
      ON launcher_login_sessions (expires_at);
    CREATE TABLE IF NOT EXISTS launcher_runtime_state (
      key TEXT PRIMARY KEY,
      value TIMESTAMPTZ NOT NULL
    );
  `);
  schemaReady = true;
}

async function getPersistentCooldownSeconds() {
  if (!pool || !schemaReady) return 0;
  const result = await pool.query(
    "SELECT value FROM launcher_runtime_state WHERE key = 'discord_oauth_cooldown'"
  );
  return result.rowCount
    ? Math.max(0, Math.ceil((new Date(result.rows[0].value).getTime() - Date.now()) / 1000))
    : 0;
}

async function setPersistentCooldown(seconds) {
  if (!pool || !schemaReady) return;
  const until = new Date(Date.now() + Math.max(1, seconds) * 1000);
  await pool.query(`
    INSERT INTO launcher_runtime_state (key, value)
    VALUES ('discord_oauth_cooldown', $1)
    ON CONFLICT (key) DO UPDATE
    SET value = GREATEST(launcher_runtime_state.value, EXCLUDED.value)
  `, [until]);
}

function getBearerToken(req) {
  const match = String(req.get('authorization') || '').match(/^Bearer\\s+([a-f0-9]{64})$/i);
  return match ? match[1] : null;
}

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  if (!/^[a-f0-9]+$/i.test(a) || !/^[a-f0-9]+$/i.test(b)) {
    return false;
  }

  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');

  return left.length === right.length &&
    left.length > 0 &&
    crypto.timingSafeEqual(left, right);
}

function getRetryAfterSeconds(response, body) {
  const header = response.headers.get('retry-after');

  if (header !== null && header.trim() !== '') {
    const seconds = Number(header);

    if (Number.isFinite(seconds) && seconds >= 0) {
      return seconds;
    }

    const dateMs = Date.parse(header);

    if (Number.isFinite(dateMs)) {
      return Math.max(0, (dateMs - Date.now()) / 1000);
    }
  }

  if (body && body.retry_after !== undefined) {
    const seconds = Number(body.retry_after);

    if (Number.isFinite(seconds) && seconds >= 0) {
      return seconds;
    }
  }

  return null;
}

async function isWhitelisted(discordUserId) {
  let credentials;

  try {
    credentials = JSON.parse(
      process.env.GOOGLE_SERVICE_ACCOUNT_JSON
    );
  } catch {
    throw new Error('Google service account JSON is invalid');
  }

  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: [
      'https://www.googleapis.com/auth/spreadsheets.readonly'
    ]
  });

  const sheets = google.sheets({
    version: 'v4',
    auth
  });

  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: GOOGLE_SHEET_ID,
    range: SHEET_RANGE
  });

  const rows = result.data.values || [];

  return rows.some((row) =>
    String(row?.[0] ?? '').trim() === String(discordUserId).trim()
  );
}

app.get('/health', async (_req, res) => {
  const missing = missingConfig();
  let database = 'unavailable';
  if (pool) {
    try {
      await pool.query('SELECT 1');
      database = schemaReady ? 'connected' : 'initializing';
    } catch (error) {
      console.error('Database health check failed:', error.message);
    }
  }
  const ok = missing.length === 0 && database === 'connected';
  return res.status(ok ? 200 : 503).json({
    ok, service: 'hshonad-backend', database, missing
  });
});

app.post('/api/launcher/device-sessions', async (_req, res) => {
  cleanExpiredData();
  if (!requireDatabase(res)) return;

  const persistentCooldown = await getPersistentCooldownSeconds().catch(() => 0);
  const cooldownRemaining = Math.max(
    persistentCooldown,
    Math.ceil((discordOAuthRateLimitedUntil - Date.now()) / 1000)
  );

  if (cooldownRemaining > 0) {
    res.set('Retry-After', String(cooldownRemaining));
    return res.status(429).json({
      error: 'discord_rate_limited',
      message: 'Discord is temporarily limiting login requests. The server is pausing new login attempts to avoid extending the limit.'
    });
  }

  const missing = missingConfig();

  if (missing.length > 0) {
    return res.status(503).json({
      error: 'server_not_configured',
      missing
    });
  }

  const id = randomToken(24);
  const secret = randomToken(32);
  const state = randomToken(32);
  const expiresAt = Date.now() + SESSION_TTL_MS;

  sessions.set(id, {
    id,
    secretHash: hashSecret(secret),
    status: 'pending',
    expiresAt,
    completedAt: null,
    discordUserId: null
  });

  oauthStates.set(state, {
    sessionId: id,
    expiresAt
  });

  return res.status(201).json({
    device_session_id: id,
    device_secret: secret,
    verification_url:
      `${BASE_URL}/auth/discord?state=${encodeURIComponent(state)}`,
    expires_in: Math.floor(SESSION_TTL_MS / 1000)
  });
});

app.get('/auth/discord', (req, res) => {
  cleanExpiredData();

  const state = String(req.query.state || '');
  const entry = oauthStates.get(state);

  if (!entry || entry.expiresAt <= Date.now()) {
    return res.status(400).send(page(
      'ลิงก์หมดอายุ',
      'กลับไปที่ Launcher แล้วเริ่ม Login ใหม่'
    ));
  }

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: 'code',
    redirect_uri: `${BASE_URL}/auth/discord/callback`,
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
  const entry = oauthStates.get(state);

  if (!entry || entry.expiresAt <= Date.now()) {
    return res.status(400).send(page(
      'คำขอหมดอายุ',
      'กลับไปที่ Launcher แล้วเริ่ม Login ใหม่'
    ));
  }

  // ใช้ state ได้ครั้งเดียว
  oauthStates.delete(state);

  const session = sessions.get(entry.sessionId);

  if (!session || session.expiresAt <= Date.now()) {
    return res.status(400).send(page(
      'Session หมดอายุ',
      'กลับไปที่ Launcher แล้วเริ่ม Login ใหม่'
    ));
  }

  if (session.status !== 'pending') {
    return res.status(409).send(page(
      'คำขอนี้ถูกใช้แล้ว',
      'กลับไปตรวจสอบสถานะใน Launcher'
    ));
  }

  if (req.query.error) {
    session.status = 'denied';
    session.completedAt = Date.now();

    return res.status(400).send(page(
      'ยกเลิกการ Login',
      'คุณไม่ได้อนุญาตการเชื่อมต่อ Discord'
    ));
  }

  const code = String(req.query.code || '');

  if (!code) {
    session.status = 'error';
    session.completedAt = Date.now();

    return res.status(400).send(page(
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

    // อ่าน response เพียงครั้งเดียว
    const rawBody = await tokenResponse.text();

    let tokenData = {};

    try {
      tokenData = JSON.parse(rawBody);
    } catch {
      tokenData = {};
    }

    if (!tokenResponse.ok) {
      const retryAfter = getRetryAfterSeconds(
        tokenResponse,
        tokenData
      );

      console.error('Discord OAuth token exchange failed:', {
        status: tokenResponse.status,
        retryAfterSeconds: retryAfter,
        scope: tokenResponse.headers.get('x-ratelimit-scope'),
        global: tokenResponse.headers.get('x-ratelimit-global'),
        error: tokenData.error || tokenData.message || 'unknown_error',
        errorDescription: tokenData.error_description || null
      });

      session.status = 'error';
      session.completedAt = Date.now();

      if (tokenResponse.status === 429) {
        // Use Discord's Retry-After only for server-side cooldown enforcement.
        // Do not show a ticking/increasing countdown to the user.
        const cooldownSeconds = retryAfter !== null
          ? Math.max(1, Math.ceil(retryAfter))
          : 60;

        discordOAuthRateLimitedUntil = Math.max(
          discordOAuthRateLimitedUntil,
          Date.now() + cooldownSeconds * 1000
        );
        await setPersistentCooldown(cooldownSeconds).catch((error) => {
          console.error('Could not persist Discord cooldown:', error.message);
        });

        return res.status(429).send(page(
          'Discord จำกัดคำขอชั่วคราว',
          'Discord กำลังจำกัดคำขอ Login ระบบหยุดรับคำขอ Login ใหม่ชั่วคราวเพื่อป้องกันการส่งคำขอซ้ำ กรุณาลองใหม่ภายหลัง'
        ));
      }

      return res.status(502).send(page(
        'Discord Login ไม่สำเร็จ',
        'ตรวจสอบ Client ID, Client Secret และ Redirect URI ในการตั้งค่า'
      ));
    }

    const accessToken = tokenData.access_token;

    if (!accessToken) {
      throw new Error('Access token missing in Discord response');
    }

    const userResponse = await fetch(
      'https://discord.com/api/users/@me',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
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

    const allowed = await isWhitelisted(discordUser.id);

    session.status = allowed ? 'approved' : 'denied';
    session.discordUserId = discordUser.id;
    session.username = String(discordUser.username || 'Discord User');
    session.avatarUrl = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
      : '';
    session.completedAt = Date.now();

    if (!allowed) {
      return res.status(403).send(page(
        'ไม่มีสิทธิ์เข้าใช้งาน',
        'ไม่พบ Discord User ID ใน Whitelist กรุณาติดต่อผู้ดูแล'
      ));
    }

    return res.send(page(
      'Login สำเร็จ',
      'ตรวจสอบ Whitelist ผ่านแล้ว กลับไปที่ Launcher ได้เลย'
    ));
  } catch (error) {
    console.error('OAuth callback processing failed:', {
      message: error.message
    });

    session.status = 'error';
    session.completedAt = Date.now();

    return res.status(500).send(page(
      'เกิดข้อผิดพลาด',
      'ระบบตรวจสอบ Login ไม่สำเร็จ กรุณาตรวจ Render Logs'
    ));
  }
});

app.get('/api/launcher/device-sessions/:id', (req, res) => {
  cleanExpiredData();

  const session = sessions.get(String(req.params.id || ''));

  if (!session || session.expiresAt <= Date.now()) {
    return res.status(404).json({
      error: 'session_not_found'
    });
  }

  const authorization = String(req.get('authorization') || '');
  const match = authorization.match(/^Bearer\s+([a-f0-9]+)$/i);

  if (!match) {
    return res.status(401).json({
      error: 'unauthorized'
    });
  }

  const providedHash = hashSecret(match[1]);

  if (!safeEqualHex(providedHash, session.secretHash)) {
    return res.status(401).json({
      error: 'unauthorized'
    });
  }

  return res.json({
    device_session_id: session.id,
    status: session.status,
    discord_user_id: session.discordUserId || '',
    username: session.username || '',
    avatar_url: session.avatarUrl || '',
    expires_in: Math.max(
      0,
      Math.floor((session.expiresAt - Date.now()) / 1000)
    )
  });
});

app.post('/api/launcher/device-sessions/:id/claim', async (req, res) => {
  if (!requireDatabase(res)) return;
  const secret = getBearerToken(req);
  if (!secret) return res.status(401).json({ error: 'unauthorized' });
  const session = sessions.get(String(req.params.id || ''));
  if (!session || session.expiresAt <= Date.now()) {
    return res.status(404).json({ error: 'session_not_found' });
  }
  if (!safeEqualHex(hashSecret(secret), session.secretHash)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (session.status !== 'approved' || !session.discordUserId) {
    return res.status(403).json({ error: 'whitelist_verification_required' });
  }
  try {
    // Verify whitelist again immediately before issuing a persistent session.
    if (!(await isWhitelisted(session.discordUserId))) {
      session.status = 'denied';
      return res.status(403).json({ error: 'not_whitelisted' });
    }
    const token = randomToken(32);
    const expiresAt = new Date(Date.now() + LOGIN_SESSION_TTL_MS);
    await pool.query(`
      INSERT INTO launcher_login_sessions
        (token_hash, discord_user_id, username, avatar_url, expires_at)
      VALUES ($1, $2, $3, $4, $5)
    `, [hashSecret(token), String(session.discordUserId), session.username || 'Discord User', session.avatarUrl || '', expiresAt]);
    return res.status(201).json({
      session_token: token,
      expires_at: expiresAt.toISOString(),
      discord_user_id: String(session.discordUserId),
      username: session.username || 'Discord User',
      avatar_url: session.avatarUrl || '',
      whitelist_status: 'Approved'
    });
  } catch (error) {
    console.error('Could not create persistent session:', error.message);
    return res.status(503).json({ error: 'session_storage_unavailable' });
  }
});

app.get('/api/launcher/sessions/validate', async (req, res) => {
  if (!requireDatabase(res)) return;
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const result = await pool.query(`
      SELECT token_hash, discord_user_id, username, avatar_url, expires_at
      FROM launcher_login_sessions
      WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
    `, [hashSecret(token)]);
    if (!result.rowCount) return res.status(401).json({ error: 'session_invalid_or_expired' });
    const session = result.rows[0];
    let allowed;
    try {
      // Always check the live whitelist at startup; a saved token is not enough.
      allowed = await isWhitelisted(session.discord_user_id);
    } catch (error) {
      console.error('Whitelist validation unavailable:', error.message);
      return res.status(503).json({ error: 'whitelist_check_unavailable' });
    }
    if (!allowed) {
      await pool.query('UPDATE launcher_login_sessions SET revoked_at = NOW() WHERE token_hash = $1', [session.token_hash]);
      return res.status(403).json({ error: 'not_whitelisted' });
    }
    return res.json({
      valid: true,
      discord_user_id: session.discord_user_id,
      username: session.username || 'Discord User',
      avatar_url: session.avatar_url || '',
      whitelist_status: 'Approved',
      expires_at: new Date(session.expires_at).toISOString()
    });
  } catch (error) {
    console.error('Session validation failed:', error.message);
    return res.status(503).json({ error: 'session_storage_unavailable' });
  }
});

app.post('/api/launcher/sessions/revoke', async (req, res) => {
  if (!requireDatabase(res)) return;
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    await pool.query('UPDATE launcher_login_sessions SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL', [hashSecret(token)]);
    return res.json({ revoked: true });
  } catch (error) {
    console.error('Session revocation failed:', error.message);
    return res.status(503).json({ error: 'session_storage_unavailable' });
  }
});

app.use('/api', (_req, res) => {
  return res.status(404).json({
    error: 'api_route_not_found'
  });
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled request error:', {
    message: err?.message || 'unknown_error'
  });

  if (res.headersSent) {
    return;
  }

  return res.status(500).json({
    error: 'internal_server_error'
  });
});

app.listen(PORT, async () => {
  console.log(`Backend listening on port ${PORT}`);
  if (!pool) {
    console.error('DATABASE_URL is not configured; persistent session endpoints are unavailable.');
    return;
  }
  try {
    await initializeSchema();
    console.log('PostgreSQL schema ready.');
  } catch (error) {
    schemaReady = false;
    console.error('PostgreSQL initialization failed:', error.message);
  }
});

process.on('SIGTERM', async () => {
  if (pool) await pool.end().catch(() => {});
  process.exit(0);
});
