equire('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN || 'kpi.eu.auth0.com';
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID || 'JIvCO5c2IBHlAe2patn6l6q5H35qxti0';
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET || '';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const AUTH0_REDIRECT_URI = process.env.AUTH0_REDIRECT_URI || `${BASE_URL}/callback`;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || ''; // optional

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'please_change_me_dev_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax'
    }
  })
);

// Serve the static index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Return current session info (for UI)
app.get('/session', (req, res) => {
  if (req.session && req.session.user) {
    const user = req.session.user;
    res.json({
      authenticated: true,
      user: {
        sub: user.sub,
        name: user.name,
        email: user.email
      }
    });
  } else {
    res.json({ authenticated: false });
  }
});

app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  req.session.oauthNonce = nonce;

  const params = new URLSearchParams({
    client_id: AUTH0_CLIENT_ID,
    redirect_uri: AUTH0_REDIRECT_URI,
    response_type: 'code',
    response_mode: 'query',
    scope: 'openid profile email offline_access',
    state,
    nonce
  });
  if (AUTH0_AUDIENCE) params.append('audience', AUTH0_AUDIENCE);

  const authorizeUrl = `https://${AUTH0_DOMAIN}/authorize?${params.toString()}`;
  return res.redirect(authorizeUrl);
});

app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(`Auth error: ${error} – ${error_description}`);
  }
  if (!code || !state) {
    return res.status(400).send('Missing code or state.');
  }
  if (state !== req.session.oauthState) {
    return res.status(400).send('Invalid state.');
  }

  try {
    const tokenRes = await axios.post(
      `https://${AUTH0_DOMAIN}/oauth/token`,
      {
        grant_type: 'authorization_code',
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET,
        code,
        redirect_uri: AUTH0_REDIRECT_URI
      },
      { headers: { 'Content-Type': 'application/json' } }
    );

    const { access_token, id_token, refresh_token, expires_in, token_type, scope } = tokenRes.data;
    req.session.tokens = {
      access_token,
      id_token,
      refresh_token: refresh_token || req.session?.tokens?.refresh_token || null,
      expires_at: Date.now() + (expires_in * 1000)
    };

    // Fetch user profile via /userinfo (uses access_token)
    const userinfo = await axios.get(`https://${AUTH0_DOMAIN}/userinfo`, {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    req.session.user = userinfo.data;

    // Cleanup state/nonce
    delete req.session.oauthState;
    delete req.session.oauthNonce;

    return res.redirect('/');
  } catch (e) {
    console.error('Token exchange failed:', e?.response?.data || e.message);
    return res.status(500).send('Token exchange failed. Check server logs and .env.');
  }
});

function requireAuth(req, res, next) {
  if (req.session?.tokens?.access_token) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

app.get('/api/protected', requireAuth, (req, res) => {
  res.json({
    ok: true,
    user: req.session.user
  });
});
app.post('/api/refresh', async (req, res) => {
  try {
    const rt = req.session?.tokens?.refresh_token;
    if (!rt) return res.status(400).json({ error: 'no_refresh_token' });

    const r = await axios.post(
      `https://${AUTH0_DOMAIN}/oauth/token`,
      {
        grant_type: 'refresh_token',
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET,
        refresh_token: rt
      },
      { headers: { 'Content-Type': 'application/json' } }
    );

    const { access_token, id_token, refresh_token, expires_in } = r.data;
    req.session.tokens.access_token = access_token;
    if (id_token) req.session.tokens.id_token = id_token;
    if (refresh_token) req.session.tokens.refresh_token = refresh_token; // may be omitted by Auth0
    req.session.tokens.expires_at = Date.now() + expires_in * 1000;

    res.json({ ok: true, expires_at: req.session.tokens.expires_at });
  } catch (e) {
    console.error('Refresh failed:', e?.response?.data || e.message);
    res.status(500).json({ error: 'refresh_failed' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    const url = new URL(`https://${AUTH0_DOMAIN}/v2/logout`);
    url.searchParams.set('client_id', AUTH0_CLIENT_ID);
    url.searchParams.set('returnTo', BASE_URL);
    res.redirect(url.toString());
  });
});

app.listen(PORT, () => {
  console.log(`✅ App listening on ${BASE_URL}`);
  console.log('Routes: /login -> Auth0, /callback -> token exchange, /api/protected, /api/refresh, /logout');
});