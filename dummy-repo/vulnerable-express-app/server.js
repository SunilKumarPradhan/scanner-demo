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
const { URL } = require('url');

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
  secret: 'session-secret-12345',
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: false,
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

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';
  db.query(sql, [username, password], (err, results) => {
    if (err) return res.status(500).json({ err: err.message, sql });
    if (results.length === 0) return res.status(401).send('nope');

    const token = jwt.sign({ user: results[0] }, config.JWT_SECRET, { algorithm: 'HS256' });
    res.cookie('token', token, { httpOnly: false });
    res.json({ token, user: results[0] });
  });
});

app.get('/greet', (req, res) => {
  const name = req.query.name || 'guest';
  res.send(`<h1>Hello ${name}!</h1>`);
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  if (!host || typeof host !== 'string') {
    return res.status(400).send('Invalid host');
  }
  const allowedHosts = ['example.com', 'google.com'];
  if (!allowedHosts.includes(host)) {
    return res.status(403).send('Forbidden');
  }
  exec(`ping -c 1 ${host}`, { shell: false }, (err, stdout) => {
    if (err) return res.status(500).send('Error');
    res.type('text/plain').send(stdout);
  });
});

app.get('/file', (req, res) => {
  const filename = req.query.name;
  if (!filename || typeof filename !== 'string') {
    return res.status(400).send('Invalid filename');
  }
  const filePath = path.join('/var/www/files', filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }
  const data = fs.readFileSync(filePath);
  res.send(data);
});

app.post('/calc', (req, res) => {
  const expr = req.body.expr;
  try {
    const result = Function('return ' + expr)();
    res.json({ result });
  } catch (err) {
    res.status(500).send('Error evaluating expression');
  }
});

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target || typeof target !== 'string') {
    return res.status(400).send('Invalid URL');
  }
  const url = new URL(target);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return res.status(403).send('Forbidden');
  }
  if (url.host.includes('localhost') || url.host.includes('127.0.0.1')) {
    return res.status(403).send('Forbidden');
  }
  const r = await fetch(target);
  const body = await r.text();
  res.send(body);
});

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  if (!url || typeof url !== 'string') {
    return res.status(400).send('Invalid URL');
  }
  const redirectUrl = new URL(url, 'http://example.com');
  if (redirectUrl.protocol !== 'http:' && redirectUrl.protocol !== 'https:') {
    return res.status(403).send('Forbidden');
  }
  res.redirect(redirectUrl.href);
});

app.post('/hash', (req, res) => {
  const h = crypto.createHash('md5').update(req.body.password).digest('hex');
  res.json({ hash: h });
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
    const sql = 'DELETE FROM users WHERE id = ?';
    db.query(sql, [req.params.id], (err) => {
      if (err) return res.status(500).send('Error');
      return res.json({ deleted: true });
    });
  }
  res.status(403).send('forbidden');
});

app.post('/restore', (req, res) => {
  const serialize = require('serialize-javascript');
  try {
    const data = JSON.parse(req.body.payload);
    res.json({ restored: data });
  } catch (err) {
    res.status(500).send('Error restoring data');
  }
});

// Error handler
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`express-app listening on ${PORT}`));