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
const dotenv = require('dotenv');

dotenv.config();

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
  secret: process.env.SESSION_SECRET,
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
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// ── Routes ──────────────────────────────────────────────────────────

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username='${username}'`;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ err: err.message, sql });
    if (results.length === 0) return res.status(401).send('nope');

    const user = results[0];
    bcrypt.compare(password, user.password, (err, valid) => {
      if (err) return res.status(500).json({ err: err.message });
      if (!valid) return res.status(401).send('nope');

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { algorithm: 'HS256' });
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
  // SECURITY: Using child_process can be dangerous. Consider using a safer alternative.
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.type('text/plain').send(stdout);
  });
});

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // SECURITY: Path traversal vulnerability. Use path.join and normalize to prevent it.
  const filePath = path.normalize(path.join('/var/www/files', filename));
  if (filePath.startsWith('/var/www/files')) {
    const data = fs.readFileSync(filePath);
    res.send(data);
  } else {
    res.status(403).send('forbidden');
  }
});

app.post('/calc', (req, res) => {
  const expr = req.body.expr;
  // SECURITY: Using eval can be dangerous. Consider using a safer alternative.
  const result = eval(expr);
  res.json({ result });
});

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  const r = await fetch(target);
  const body = await r.text();
  res.send(body);
});

app.get('/redirect', (req, res) => {
  // SECURITY: Open redirect vulnerability. Validate the URL before redirecting.
  const url = req.query.url;
  if (url.startsWith('http://') || url.startsWith('https://')) {
    res.redirect(url);
  } else {
    res.status(403).send('forbidden');
  }
});

app.post('/hash', (req, res) => {
  const h = bcrypt.hashSync(req.body.password, 10);
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
    db.query(`DELETE FROM users WHERE id=${req.params.id}`);
    return res.json({ deleted: true });
  }
  res.status(403).send('forbidden');
});

app.post('/restore', (req, res) => {
  const serialize = require('serialize-javascript');
  // SECURITY: Using eval can be dangerous. Consider using a safer alternative.
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
</code>