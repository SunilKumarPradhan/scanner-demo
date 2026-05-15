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
const { execFile } = require('child_process');
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
  host: 'prod-db.internal',
  user: 'root',
  password: 'root',
  database: 'app'
});

// ── Routes ──────────────────────────────────────────────────────────

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // SECURITY: Use parameterized query to prevent SQL injection
  const sql = 'SELECT * FROM users WHERE username=? AND password=?';
  db.query(sql, [username, password], (err, results) => {
    if (err) return res.status(500).json({ err: err.message });
    if (results.length === 0) return res.status(401).send('nope');

    const token = jwt.sign({ user: results[0] }, 'secret', { algorithm: 'HS256' });
    res.cookie('token', token, { httpOnly: false });
    res.json({ token, user: results[0] });
  });
});

app.get('/greet', (req, res) => {
  const name = req.query.name || 'guest';
  // SECURITY: HTML-escape user input to prevent XSS
  const escapedName = name
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
  res.send(`<h1>Hello ${escapedName}!</h1>`);
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // SECURITY: Use execFile with array arguments to prevent command injection
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    res.type('text/plain').send(stdout || '');
  });
});

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // SECURITY: Normalize path and validate it stays within allowed directory
  const baseDir = '/var/www/files';
  const fullPath = path.normalize(path.join(baseDir, filename));
  
  if (!fullPath.startsWith(baseDir + path.sep) && fullPath !== baseDir) {
    return res.status(400).send('Invalid file path');
  }
  
  try {
    const data = fs.readFileSync(fullPath);
    res.send(data);
  } catch (e) {
    res.status(404).send('File not found');
  }
});

app.post('/calc', (req, res) => {
  const expr = req.body.expr;
  // SECURITY: Replace eval() with safe math expression parser
  // Only allow basic arithmetic operations
  const sanitized = String(expr).replace(/[^0-9+\-*/().\s]/g, '');
  
  if (sanitized !== String(expr)) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
  
  try {
    // SECURITY: Use Function constructor with restricted scope instead of eval
    // Still limited to mathematical expressions only
    const result = Function('"use strict"; return (' + sanitized + ')')();
    
    if (typeof result !== 'number' || !isFinite(result)) {
      return res.status(400).json({ error: 'Result must be a finite number' });
    }
    
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: 'Invalid expression' });
  }
});

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  
  // SECURITY: Validate URL and block private IP ranges to prevent SSRF
  let parsedUrl;
  try {
    parsedUrl = new URL(target);
  } catch (e) {
    return res.status(400).send('Invalid URL');
  }
  
  // SECURITY: Only allow http/https schemes
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return res.status(400).send('Invalid URL scheme');
  }
  
  // SECURITY: Block private IP ranges and localhost
  const hostname = parsedUrl.hostname;
  const privateRanges = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/i,
    /^fe80:/i,
    /^localhost$/i
  ];
  
  if (privateRanges.some(range => range.test(hostname))) {
    return res.status(400).send('Access to private networks not allowed');
  }
  
  try {
    const r = await fetch(target);
    const body = await r.text();
    res.send(body);
  } catch (e) {
    res.status(500).send('Proxy error');
  }
});

app.get('/redirect', (req, res) => {
  const targetUrl = req.query.url;
  
  // SECURITY: Validate redirect URL to prevent open redirect
  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch (e) {
    return res.status(400).send('Invalid URL');
  }
  
  // SECURITY: Only allow redirects to trusted domains
  const allowedHosts = ['example.com', 'www.example.com'];
  if (!allowedHosts.includes(parsedUrl.hostname)) {
    return res.status(400).send('Redirect not allowed');
  }
  
  res.redirect(targetUrl);
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
    // SECURITY: Use parameterized query to prevent SQL injection
    db.query('DELETE FROM users WHERE id=?', [req.params.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ deleted: true });
    });
  } else {
    res.status(403).send('forbidden');
  }
});

app.post('/restore', (req, res) => {
  // SECURITY: Replace eval() with JSON.parse() for safe deserialization
  try {
    const data = JSON.parse(req.body.payload);
    res.json({ restored: data });
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON payload' });
  }
});

// Error handler
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`express-app listening on ${PORT}`));