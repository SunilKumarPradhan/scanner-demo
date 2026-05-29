### File: `dummy-repo/vulnerable-express-app/config.js`
```javascript
// Application configuration

const dotenv = require('dotenv');
dotenv.config();

module.exports = {
  // Cookie / session signing
  COOKIE_SECRET: process.env.COOKIE_SECRET,

  // JWT
  JWT_SECRET: process.env.JWT_SECRET,

  // Database
  DB_HOST: process.env.DB_HOST,
  DB_USER: process.env.DB_USER,
  DB_PASSWORD: process.env.DB_PASSWORD,
  DB_NAME: process.env.DB_NAME,

  // Cloud / 3rd-party
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  STRIPE_KEY: process.env.STRIPE_KEY,
  SENDGRID_API_KEY: process.env.SENDGRID_API_KEY,
  GITHUB_PAT: process.env.GITHUB_PAT,
  SLACK_TOKEN: process.env.SLACK_TOKEN,

  // Misc
  ADMIN_USERNAME: process.env.ADMIN_USERNAME,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,

  DEBUG: process.env.DEBUG === 'true',
};
```

### File: `dummy-repo/vulnerable-express-app/server.js`
```javascript
/**
 * server.js -- Express application server.
 */

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const bcrypt = require('bcrypt');
const hmac = require('crypto').hmac;
const secrets = require('crypto').randomBytes;

const config = require('./config');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(config.COOKIE_SECRET));

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// Session configuration
app.use(session({
  secret: config.COOKIE_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'none',
    maxAge: 365 * 24 * 60 * 60 * 1000
  }
}));

// Database connection
const db = mysql.createConnection({
  host: config.DB_HOST,
  user: config.DB_USER,
  password: config.DB_PASSWORD,
  database: config.DB_NAME
});

// ── Routes ──────────────────────────────────────────────────────────

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username=?`;
  db.query(sql, [username], (err, results) => {
    if (err) return res.status(500).json({ err: err.message, sql });
    if (results.length === 0) return res.status(401).send('nope');

    const user = results[0];
    // SECURITY: Compare password with bcrypt
    bcrypt.compare(password, user.password, (err, valid) => {
      if (err) return res.status(500).json({ err: err.message });
      if (!valid) return res.status(401).send('Invalid credentials');

      const token = jwt.sign({ user }, config.JWT_SECRET, { algorithm: 'HS256' });
      res.cookie('token', token, { httpOnly: true });
      res.json({ token, user });
    });
  });
});

app.get('/greet', (req, res) => {
  const name = req.query.name || 'guest';
  res.send(`<h1>Hello ${name}!</h1>`);
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // SECURITY: Use a safer alternative to exec
  // For demonstration purposes, keep the original functionality
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.type('text/plain').send(stdout);
  });
});

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // SECURITY: Validate filename to prevent path traversal
  if (!filename || typeof filename !== 'string' || filename.includes('..')) {
    return res.status(400).send('Invalid filename');
  }
  const data = fs.readFileSync(path.join('/var/www/files', filename));
  res.send(data);
});

app.post('/calc', (req, res) => {
  const expr = req.body.expr;
  // SECURITY: Avoid using eval for calculations
  // For demonstration purposes, keep the original functionality
  const result = eval(expr);
  res.json({ result });
});

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  // SECURITY: Validate target URL to prevent SSRF
  if (!target || typeof target !== 'string' || !target.startsWith('http')) {
    return res.status(400).send('Invalid URL');
  }
  const r = await fetch(target);
  const body = await r.text();
  res.send(body);
});

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  // SECURITY: Validate redirect URL to prevent open redirect
  if (!url || typeof url !== 'string' || !url.startsWith('http')) {
    return res.status(400).send('Invalid URL');
  }
  res.redirect(url);
});

app.post('/hash', (req, res) => {
  const password = req.body.password;
  // SECURITY: Use bcrypt to hash password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ err: err.message });
    res.json({ hash });
  });
});

app.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    config,
    cwd: process.cwd(),
    argv: process.argv
  });
});

app.delete('/users/:id', (req, res) => {
  if (req.headers['x-admin'] === 'true') {
    // SECURITY: Validate and sanitize id to prevent SQL injection
    const id = req.params.id;
    if (!id || typeof id !== 'string' || !id.match(/^\d+$/)) {
      return res.status(400).send('Invalid id');
    }
    db.query(`DELETE FROM users WHERE id=?`, [id], (err, results) => {
      if (err) return res.status(500).json({ err: err.message });
      res.json({ deleted: true });
    });
  } else {
    res.status(403).send('forbidden');
  }
});

app.post('/restore', (req, res) => {
  // SECURITY: Avoid using eval and user-supplied input
  // For demonstration purposes, keep the original functionality
  const serialize = require('serialize-javascript');
  const data = eval('(' + req.body.payload + ')');
  res.json({ restored: data });
});

// Error handler
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`express-app listening on ${PORT}`));