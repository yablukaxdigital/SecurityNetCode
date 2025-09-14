require('dotenv').config();
const axios = require('axios');
const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const cookie = require('cookie');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const port = process.env.PORT || 3000;
const SESSION_HEADER = 'Authorization';
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN; // e.g. kpi.eu.auth0.com
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || undefined; // optional API Audience
const AUTH0_DB_CONNECTION = process.env.AUTH0_DB_CONNECTION || 'Username-Password-Authentication';
const REFRESH_WINDOW_SECONDS = Number(process.env.REFRESH_WINDOW_SECONDS || 60);

if (!AUTH0_DOMAIN || !AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET) {
  console.error('❌ Missing required .env: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET');
  process.exit(1);
}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

class SessionStore {
  #sessions = {};
  constructor(file = './sessions.json') {
    this.file = file;
    try {
      const raw = fs.readFileSync(this.file, 'utf8');
      this.#sessions = JSON.parse(raw.trim() || '{}');
    } catch (_) {
      this.#sessions = {};
    }
  }
  #persist() { fs.writeFileSync(this.file, JSON.stringify(this.#sessions, null, 2), 'utf-8'); }
  create(initial = {}) {
    const id = uuid.v4();
    this.#sessions[id] = initial;
    this.#persist();
    return id;
  }
  get(id) { return this.#sessions[id]; }
  set(id, value) { this.#sessions[id] = value; this.#persist(); }
  destroy(id) { delete this.#sessions[id]; this.#persist(); }
}
const sessions = new SessionStore(path.join(__dirname, 'sessions.json'));

app.use((req, res, next) => {
  let header = req.get(SESSION_HEADER);
  let sid = null;

  if (header && header.toLowerCase().startsWith('bearer ')) sid = header.slice(7).trim();
  else if (header) sid = header.trim();

  if (!sid && req.headers.cookie) {
    try {
      const parsed = cookie.parse(req.headers.cookie);
      if (parsed.sid) sid = parsed.sid;
    } catch(_) {}
  }

  if (!sid || !sessions.get(sid)) sid = sessions.create({});
  req.sessionId = sid;
  req.session = sessions.get(sid) || {};
  onFinished(req, () => sessions.set(req.sessionId, req.session));
  next();
});

const tokenUrl = `https://${AUTH0_DOMAIN}/oauth/token`;
const userInfoUrl = `https://${AUTH0_DOMAIN}/userinfo`;

async function passwordRealmLogin({ username, password }) {
  const payload = {
    grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
    realm: AUTH0_DB_CONNECTION,
    username,
    password,
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET,
    scope: 'openid profile email offline_access'
  };
  if (AUTH0_AUDIENCE) payload.audience = AUTH0_AUDIENCE;
  const { data } = await axios.post(tokenUrl, payload, { headers: { 'Content-Type': 'application/json' } });
  return data; 
}

async function refreshGrant(refresh_token) {
  const payload = {
    grant_type: 'refresh_token',
    refresh_token,
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET
  };
  if (AUTH0_AUDIENCE) payload.audience = AUTH0_AUDIENCE;
  const { data } = await axios.post(tokenUrl, payload, { headers: { 'Content-Type': 'application/json' } });
  return data;
}

// ---------- JWKS + ID Token verification ----------
const jwks = jwksClient({
  jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000, // 10 min
  rateLimit: true,
  jwksRequestsPerMinute: 5
});

function getKey(header, cb) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return cb(err);
    const signingKey = key.getPublicKey();
    cb(null, signingKey);
  });
}

function verifyIdToken(idToken) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      getKey,
      {
        algorithms: ['RS256'],
        issuer: `https://${AUTH0_DOMAIN}/`,
        audience: AUTH0_CLIENT_ID
      },
      (err, decoded) => (err ? reject(err) : resolve(decoded))
    );
  });
}

async function requireValidIdToken(req, res, next) {
  try {
    const s = req.session.tokens;
    if (!s?.id_token) return res.status(401).json({ error: 'no_id_token' });
    req.idClaims = await verifyIdToken(s.id_token);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_id_token', details: e.message });
  }
}

// ---------- Routes ----------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/logout', (req, res) => {
  if (req.sessionId) sessions.destroy(req.sessionId);
  res.setHeader('Set-Cookie', cookie.serialize('sid', '', {
    httpOnly: true,
    path: '/',
    expires: new Date(0),
    sameSite: 'lax'
  }));
  res.redirect('/');
});

app.post('/api/login', async (req, res) => {
  try {
    const { login, password } = req.body;
    if (!login || !password) return res.status(400).json({ error: 'login and password are required' });

    const t = await passwordRealmLogin({ username: login, password });
    const { access_token, id_token, refresh_token, expires_in } = t;
    const expires_at = Date.now() + (Number(expires_in) * 1000);

    req.session.tokens = { access_token, id_token, refresh_token, expires_at };
    res.setHeader('Set-Cookie', cookie.serialize('sid', req.sessionId, {
  httpOnly: true,
  path: '/',
  sameSite: 'lax'
}));
return res.json({ token: req.sessionId });
  } catch (e) {
    console.error('Login error:', e.response?.data || e.message);
    res.status(401).json({ error: 'invalid_credentials', details: e.response?.data || e.message });
  }
});

app.get('/me', requireValidIdToken, async (req, res) => {
  try {
    const s = req.session.tokens;
    if (!s?.access_token) return res.status(401).json({ error: 'no_session' });

    const secondsLeft = Math.floor((s.expires_at - Date.now()) / 1000);
    if (secondsLeft <= REFRESH_WINDOW_SECONDS && s.refresh_token) {
      try {
        const refreshed = await refreshGrant(s.refresh_token);
        s.access_token = refreshed.access_token || s.access_token;
        s.id_token = refreshed.id_token || s.id_token;
        if (refreshed.refresh_token) s.refresh_token = refreshed.refresh_token;
        if (refreshed.expires_in) s.expires_at = Date.now() + Number(refreshed.expires_in) * 1000;
        req.session.tokens = s;
      } catch (err) {
        console.warn('Refresh failed:', err.response?.data || err.message);
        return res.status(401).json({ error: 'session_expired' });
      }
    }

    // pull profile
    const { data: profile } = await axios.get(userInfoUrl, {
      headers: { Authorization: `Bearer ${req.session.tokens.access_token}` }
    });

    res.json({ username: profile.name || profile.nickname || profile.email || 'User', profile, id_claims: req.idClaims });
  } catch (e) {
    console.error('ME error:', e.response?.data || e.message);
    res.status(401).json({ error: 'unauthorized' });
  }
});

app.get('/api/verify', requireValidIdToken, (req, res) => {
  res.json({ status: 'ok', claims: req.idClaims });
});

app.listen(port, () => {
  console.log(`✅ App listening on http://localhost:${port}`);
});
