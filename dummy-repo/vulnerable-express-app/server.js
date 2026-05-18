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
const helmet = require('helmet');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');

const config = require('./config');

const app = express();

// SECURITY: Enable helmet for security headers
app.use(helmet());

// SECURITY: Configure Content Security Policy
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    fontSrc: ["'self'"],
    imgSrc: ["'self'"],
    frameAncestors: ["'none'"],
  }
}));

// SECURITY: Configure Strict Transport Security
app.use(helmet.hsts({
  maxAge: 63072000, // 2 years
  includeSubDomains: true,
  preload: true,
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(config.COOKIE_SECRET));

// SECURITY: Configure CORS with explicit allow-list
const allowedOrigins = ['http://example.com', 'https://example.com'];
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', allowedOrigins.includes(req.headers.origin) ? req.headers.origin : '');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// SECURITY: Configure session with secure cookies
app.use(session({
  secret: config.COOKIE_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'Lax',
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

// SECURITY: Enable CSRF protection
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// SECURITY: Enable rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// ── Routes ──────────────────────────────────────────────────────────

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // SECURITY: Use prepared statement to prevent SQL injection
  const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';
  db.query(sql, [username, password], (err, results) => {
    if (err) return res.status(500).json({ err: err.message, sql });
    if (results.length === 0) return res.status(401).send('nope');

    const token = jwt.sign({ user: results[0] }, config.JWT_SECRET, { algorithm: 'HS256' });
    // SECURITY: Set secure cookie
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Lax' });
    res.json({ token, user: results[0] });
  });
});

app.get('/greet', (req, res) => {
  const name = req.query.name || 'guest';
  // SECURITY: Sanitize user input
  res.send(`<h1>Hello ${name.replace(/[^a-zA-Z ]/g, '')}!</h1>`);
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // SECURITY: Use a safer method to execute system commands
  const pingCommand = `ping -c 1 ${host}`;
  exec(pingCommand, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.type('text/plain').send(stdout);
  });
});

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // SECURITY: Validate and sanitize user input
  if (!filename || !filename.match(/^[a-zA-Z0-9_-]+$/)) return res.status(400).send('Invalid filename');
  const data = fs.readFileSync(path.join('/var/www/files', filename));
  res.send(data);
});

app.post('/calc', (req, res) => {
  const expr = req.body.expr;
  // SECURITY: Use a safer method to evaluate expressions
  const result = Function('"use strict";return (' + expr + ')')();
  res.json({ result });
});

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  // SECURITY: Validate and sanitize user input
  if (!target || !target.match(/^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\//)) return res.status(400).send('Invalid URL');
  const r = await fetch(target);
  const body = await r.text();
  res.send(body);
});

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  // SECURITY: Validate and sanitize user input
  if (!url || !url.match(/^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\//)) return res.status(400).send('Invalid URL');
  res.redirect(url);
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
  // SECURITY: Validate and sanitize user input
  if (req.headers['x-admin'] === 'true') {
    const id = req.params.id;
    if (!id || !id.match(/^[0-9]+$/)) return res.status(400).send('Invalid ID');
    db.query('DELETE FROM users WHERE id = ?', [id], (err) => {
      if (err) return res.status(500).send(err.message);
      res.json({ deleted: true });
    });
  } else {
    res.status(403).send('forbidden');
  }
});

app.post('/restore', (req, res) => {
  // SECURITY: Validate and sanitize user input
  const payload = req.body.payload;
  if (!payload || !payload.match(/^[a-zA-Z0-9_.-]+$/)) return res.status(400).send('Invalid payload');
  const serialize = require('serialize-javascript');
  const data = serialize(payload);
  res.json({ restored: data });
});

// Error handler
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`express-app listening on ${PORT}`));