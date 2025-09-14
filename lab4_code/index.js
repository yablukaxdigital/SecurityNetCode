require('dotenv').config();
const axios = require('axios');
const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

// ---------- Config ----------
const port = process.env.PORT || 3000;
const SESSION_HEADER = 'Authorization';
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN; // e.g. dev-xxxxx.us.auth0.com
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || undefined; // optional
const AUTH0_DB_CONNECTION = process.env.AUTH0_DB_CONNECTION || 'Username-Password-Authentication';
const REFRESH_WINDOW_SECONDS = Number(process.env.REFRESH_WINDOW_SECONDS || 60);

if (!AUTH0_DOMAIN || !AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET) {
  console.error('❌ Missing required .env: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET');
  process.exit(1);
}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ---------- Tiny file-backed session (opaque token we issue to the browser) ----------
class SessionStore {
  #sessions = {};
  constructor(file = './sessions.json') {
    this.file = file;
    try {
      const raw = fs.readFileSync(this.file, 'utf8');
      this.#sessions = JSON.parse(raw.trim() || '{}');
    } catch (e) {
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

// Attach session to each request using "Authorization: Bearer <opaqueSessionId>"
app.use((req, res, next) => {
  let header = req.get(SESSION_HEADER);
  let sid = null;

  if (header && header.toLowerCase().startsWith('bearer ')) {
    sid = header.slice(7).trim();
  } else if (header) {
    // backward compatibility if header is just the id
    sid = header.trim();
  }

  if (!sid || !sessions.get(sid)) {
    // create a new empty session
    sid = sessions.create({});
  }

  req.sessionId = sid;
  req.session = sessions.get(sid) || {};

  onFinished(req, () => sessions.set(req.sessionId, req.session));
  next();
});

// ---------- Auth0 endpoints ----------
const auth0TokenUrl = `https://${AUTH0_DOMAIN}/oauth/token`;
const auth0UserInfoUrl = `https://${AUTH0_DOMAIN}/userinfo`;
const auth0MgmtAudience = `https://${AUTH0_DOMAIN}/api/v2/`;

// Exchange username/password using PASSWORD-REALM (explicit DB connection)
async function passwordGrant({ username, password }) {
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

  const { data } = await axios.post(auth0TokenUrl, payload, {
    headers: { 'Content-Type': 'application/json' }
  });
  return data; // { access_token, id_token, expires_in, refresh_token? }
}

// Refresh tokens using refresh_token grant
async function refreshGrant(refresh_token) {
  const payload = {
    grant_type: 'refresh_token',
    refresh_token,
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET
  };
  if (AUTH0_AUDIENCE) payload.audience = AUTH0_AUDIENCE;

  const { data } = await axios.post(auth0TokenUrl, payload, {
    headers: { 'Content-Type': 'application/json' }
  });
  return data;
}

// (Bonus) Get Management API token (Client Credentials grant)
async function getManagementToken() {
  const payload = {
    grant_type: 'client_credentials',
    client_id: process.env.MGMT_CLIENT_ID || AUTH0_CLIENT_ID,
    client_secret: process.env.MGMT_CLIENT_SECRET || AUTH0_CLIENT_SECRET,
    audience: auth0MgmtAudience
  };
  const { data } = await axios.post(auth0TokenUrl, payload, {
    headers: { 'Content-Type': 'application/json' }
  });
  return data.access_token;
}

// Helper: check if DB connection requires username
async function connectionRequiresUsername(mgmtToken) {
  try {
    const url = `https://${AUTH0_DOMAIN}/api/v2/connections`;
    const { data } = await axios.get(url, {
      params: { name: AUTH0_DB_CONNECTION, strategy: 'auth0' },
      headers: { Authorization: `Bearer ${mgmtToken}` }
    });
    const conn = Array.isArray(data) ? data[0] : data;
    return Boolean(conn && conn.options && conn.options.requires_username);
  } catch (e) {
    console.warn('Could not fetch connection settings, defaulting to NO username:', e.response?.data || e.message);
    return false;
  }
}

// ---------- Routes ----------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/logout', (req, res) => {
  sessions.destroy(req.sessionId);
  res.redirect('/');
});

app.post('/api/login', async (req, res) => {
  try {
    const { login, password } = req.body;
    if (!login || !password) return res.status(400).json({ error: 'login and password are required' });

    const tokenResponse = await passwordGrant({ username: login, password });
    const { access_token, id_token, refresh_token, expires_in } = tokenResponse;

    const expiresAt = Date.now() + (Number(expires_in) * 1000);
    req.session.tokens = {
      access_token,
      id_token,
      refresh_token, // keep refresh token only on server side
      expires_at: expiresAt
    };

    return res.json({ token: req.sessionId });
  } catch (e) {
    console.error('Login error:', e.response?.data || e.message);
    return res.status(401).json({ error: 'invalid_credentials' });
  }
});

// (Bonus) Create user via Management API (DB connection)
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

    const mgmtToken = await getManagementToken();
    const allowUsername = await connectionRequiresUsername(mgmtToken);

    const payload = {
      email,
      password,
      connection: AUTH0_DB_CONNECTION,
    };
    if (allowUsername && username) payload.username = username;

    const { data } = await axios.post(
      `https://${AUTH0_DOMAIN}/api/v2/users`,
      payload,
      { headers: { Authorization: `Bearer ${mgmtToken}`, 'Content-Type': 'application/json' } }
    );

    return res.json({ user_id: data.user_id, email: data.email, used_username: allowUsername && Boolean(username) });
  } catch (e) {
    console.error('Signup error:', e.response?.data || e.message);
    return res.status(400).json({ error: 'signup_failed', details: e.response?.data || e.message });
  }
});

app.get('/me', async (req, res) => {
  try {
    const s = req.session.tokens;
    if (!s?.access_token) return res.status(401).json({ error: 'no_session' });

    // Auto-refresh close to expiry
    const secondsLeft = Math.floor((s.expires_at - Date.now()) / 1000);
    if (secondsLeft <= REFRESH_WINDOW_SECONDS && s.refresh_token) {
      try {
        const refreshed = await refreshGrant(s.refresh_token);
        s.access_token = refreshed.access_token || s.access_token;
        s.id_token = refreshed.id_token || s.id_token;
        if (refreshed.refresh_token) s.refresh_token = refreshed.refresh_token; // rotation
        if (refreshed.expires_in) s.expires_at = Date.now() + Number(refreshed.expires_in) * 1000;
        req.session.tokens = s;
      } catch (refreshErr) {
        console.warn('Refresh failed, clearing session:', refreshErr.response?.data || refreshErr.message);
        sessions.destroy(req.sessionId);
        return res.status(401).json({ error: 'session_expired' });
      }
    }

    // Fetch profile
    const { data: profile } = await axios.get(auth0UserInfoUrl, {
      headers: { Authorization: `Bearer ${req.session.tokens.access_token}` }
    });

    const username = profile.name || profile.nickname || profile.email || 'User';
    return res.json({ username, profile });
  } catch (e) {
    console.error('ME error:', e.response?.data || e.message);
    return res.status(401).json({ error: 'unauthorized' });
  }
});

app.listen(port, () => {
  console.log(`✅ App listening on http://localhost:${port}`);
});
