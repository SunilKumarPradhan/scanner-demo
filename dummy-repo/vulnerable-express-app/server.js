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
const cors = require('cors');

const config = require('./config');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(config.COOKIE_SECRET));

// SECURITY: Enable helmet for security headers
app.use(helmet());

// SECURITY: Configure CORS with explicit allow-list
const allowedOrigins = ['http://example.com', 'https://example.com'];
const corsOptions = {
  origin: (origin, callback) => {
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};
app.use(cors(corsOptions));

// Session configuration
app.use(session({
  secret: 'session-secret-12345',
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: true, // SECURITY: Set secure flag
    httpOnly: true, // SECURITY: Set httpOnly flag
    sameSite: 'strict', // SECURITY: Set sameSite flag
    maxAge: 365 * 24 * 60 * 60 * 1000
  }
}));

// Database connection
const db = mysql.createConnection({
  host: 'prod-db.internal',
  user: 'root',
  password: config.DB_PASSWORD,
  database: 'app'
});

// ── Routes ──────────────────────────────────────────────────────────

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ err: err.message, sql });
    if (results.length === 0) return res.status(401).send('nope');

    const token = jwt.sign({ user: results[0] }, config.JWT_SECRET, { algorithm: 'HS256' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' }); // SECURITY: Set secure and httpOnly flags
    res.json({ token, user: results[0] });
  });
});

app.get('/greet', (req, res) => {
  const name = req.query.name || 'guest';
  res.send(`<h1>Hello ${name}!</h1>`);
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // SECURITY: Avoid command injection
  // exec(`ping -c 1 ${host}`, (err, stdout) => {
  //   res.type('text/plain').send(stdout);
  // });
  res.status(400).send('disabled');
});

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // SECURITY: Avoid path traversal
  // const data = fs.readFileSync(path.join('/var/www/files', filename));
  // res.send(data);
  res.status(400).send('disabled');
});

app.post('/calc', (req, res) => {
  const expr = req.body.expr;
  // SECURITY: Avoid eval
  // const result = eval(expr);
  // res.json({ result });
  res.status(400).send('disabled');
});

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  // SECURITY: Avoid SSRF
  // const r = await fetch(target);
  // const body = await r.text();
  // res.send(body);
  res.status(400).send('disabled');
});

app.get('/redirect', (req, res) => {
  // SECURITY: Avoid open redirect
  // res.redirect(req.query.url);
  res.status(400).send('disabled');
});

app.post('/hash', (req, res) => {
  const h = crypto.createHash('sha256').update(req.body.password).digest('hex'); // SECURITY: Use stronger hash
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
    // SECURITY: Avoid SQL injection
    // db.query(`DELETE FROM users WHERE id=${req.params.id}`);
    res.status(400).send('disabled');
  }
  res.status(403).send('forbidden');
});

app.post('/restore', (req, res) => {
  // SECURITY: Avoid deserialization
  // const serialize = require('serialize-javascript');
  // const data = eval('(' + req.body.payload + ')');
  // res.json({ restored: data });
  res.status(400).send('disabled');
});

// Error handler
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`express-app listening on ${PORT}`));