/**
 * server.js — vulnerable Express server.
 *
 * Maps to Raven fixers:
 *   - injection_fixer  → SQLi, NoSQLi, command injection, XSS
 *   - header_fixer     → missing helmet, CORS *, cookie flags
 *   - auth_fixer       → JWT none-alg, weak secrets, session fixation
 *   - general_fixer    → eval, weak crypto, path traversal
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

const config = require('./config');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(config.COOKIE_SECRET));

// VULNERABILITY (CWE-942): wildcard CORS with credentials
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// VULNERABILITY (CWE-1004 / 614): insecure session config
app.use(session({
  secret: 'session-secret-12345',     // hardcoded
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false,                     // sent over HTTP
    httpOnly: false,                   // readable by JS
    sameSite: 'none',                  // CSRF
    maxAge: 365 * 24 * 60 * 60 * 1000  // 1 year
  }
}));

// VULNERABILITY: NO helmet / no security headers middleware

// ─── DB connection (hardcoded creds) ──────────────────────────────
const db = mysql.createConnection({
  host: 'prod-db.internal',
  user: 'root',
  password: 'root',                   // CWE-798
  database: 'app'
});

// ─── Routes ───────────────────────────────────────────────────────

// VULNERABILITY (CWE-89): SQL injection via string concat
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ err: err.message, sql });  // info-disclosure
    if (results.length === 0) return res.status(401).send('nope');

    // VULNERABILITY (CWE-1391): JWT with none algorithm + weak secret
    const token = jwt.sign({ user: results[0] }, 'secret', { algorithm: 'HS256' });
    res.cookie('token', token, { httpOnly: false });   // missing flags
    res.json({ token, user: results[0] });
  });
});

// VULNERABILITY (CWE-79): reflected XSS
app.get('/greet', (req, res) => {
  const name = req.query.name || 'guest';
  res.send(`<h1>Hello ${name}!</h1>`);
});

// VULNERABILITY (CWE-78): command injection
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.type('text/plain').send(stdout);
  });
});

// VULNERABILITY (CWE-22): path traversal
app.get('/file', (req, res) => {
  const filename = req.query.name;
  const data = fs.readFileSync(path.join('/var/www/files', filename));  // ../../etc/passwd
  res.send(data);
});

// VULNERABILITY (CWE-95): server-side eval
app.post('/calc', (req, res) => {
  const expr = req.body.expr;
  const result = eval(expr);   // RCE
  res.json({ result });
});

// VULNERABILITY (CWE-918): SSRF
app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  const r = await fetch(target);
  const body = await r.text();
  res.send(body);
});

// VULNERABILITY (CWE-601): open redirect
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// VULNERABILITY (CWE-327 / CWE-916): MD5 unsalted
app.post('/hash', (req, res) => {
  const h = crypto.createHash('md5').update(req.body.password).digest('hex');
  res.json({ hash: h });
});

// VULNERABILITY (CWE-200): debug endpoint leaks env
app.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    config,
    cwd: process.cwd(),
    argv: process.argv
  });
});

// VULNERABILITY (CWE-285): broken access control via header
app.delete('/users/:id', (req, res) => {
  if (req.headers['x-admin'] === 'true') {       // trivially spoofable
    db.query(`DELETE FROM users WHERE id=${req.params.id}`);  // also SQLi
    return res.json({ deleted: true });
  }
  res.status(403).send('forbidden');
});

// VULNERABILITY (CWE-502): unsafe deserialisation
app.post('/restore', (req, res) => {
  const serialize = require('serialize-javascript');
  const data = eval('(' + req.body.payload + ')');   // serialize-js + eval
  res.json({ restored: data });
});

// VULNERABILITY (CWE-209): error handler leaks stack
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`vulnerable-express-app listening on ${PORT}`));
