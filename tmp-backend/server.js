import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import morgan from 'morgan';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { signAccessToken, signRefreshToken, verifyToken } from './lib/tokens.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const ACCESS_MIN = parseInt(process.env.ACCESS_TOKEN_MINUTES || '5', 10);
const REFRESH_DAYS = parseInt(process.env.REFRESH_TOKEN_DAYS || '7', 10);
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'changeme1';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'changeme2';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:4200';

// Basic security headers
app.use(helmet({
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));
app.use(morgan('dev'));

// CORS (allow Angular dev server)
app.use(cors({
  origin: CORS_ORIGIN,
  credentials: true,
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','X-XSRF-TOKEN','Authorization']
}));

app.use(express.json());
app.use(cookieParser());

// Load users from file
const usersPath = path.join(__dirname, 'config', 'users.json');
function loadUsers(){
  const raw = fs.readFileSync(usersPath, 'utf8');
  const data = JSON.parse(raw);
  return data.users || [];
}

// Helper: set cookies
function setRefreshCookie(res, token){
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: false, // set true behind HTTPS
    sameSite: 'strict',
    path: '/auth'
  });
}
function clearRefreshCookie(res){
  res.clearCookie('refresh_token', { path: '/auth' });
}
// For Angular XSRF module: send readable cookie; we don't strictly enforce CSRF on /auth/* for demo.
app.use((req, res, next) => {
  if (!req.cookies['XSRF-TOKEN']) {
    const csrf = Math.random().toString(36).slice(2);
    res.cookie('XSRF-TOKEN', csrf, {
      httpOnly: false,
      secure: false, // set true on HTTPS
      sameSite: 'lax',
      path: '/'
    });
  }
  next();
});

// Auth routes
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: 'email and password required' });
  const users = loadUsers();
  const user = users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
  if (!user) return res.status(401).json({ message: 'invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'invalid credentials' });

  const payload = { sub: user.id, email: user.email, roles: user.roles };
  const accessToken = signAccessToken(payload, ACCESS_SECRET, ACCESS_MIN);
  const refreshToken = signRefreshToken({ sub: user.id }, REFRESH_SECRET, REFRESH_DAYS);

  setRefreshCookie(res, refreshToken);

  return res.json({
    accessToken,
    expiresIn: ACCESS_MIN * 60,
    user: { id: user.id, email: user.email, roles: user.roles }
  });
});

app.post('/auth/refresh', (req, res) => {
  const rt = req.cookies['refresh_token'];
  if (!rt) return res.status(401).json({ message: 'no refresh token' });
  try {
    const decoded = verifyToken(rt, REFRESH_SECRET);
    // In real apps, check token rotation / revocation store here
    const users = loadUsers();
    const user = users.find(u => u.id === decoded.sub);
    if (!user) return res.status(401).json({ message: 'invalid refresh' });

    const payload = { sub: user.id, email: user.email, roles: user.roles };
    const accessToken = signAccessToken(payload, ACCESS_SECRET, ACCESS_MIN);
    // Optionally rotate refresh token:
    const newRefresh = signRefreshToken({ sub: user.id }, REFRESH_SECRET, REFRESH_DAYS);
    setRefreshCookie(res, newRefresh);

    return res.json({
      accessToken,
      expiresIn: ACCESS_MIN * 60,
      user: { id: user.id, email: user.email, roles: user.roles }
    });
  } catch (e) {
    return res.status(401).json({ message: 'invalid refresh' });
  }
});

app.post('/auth/logout', (req, res) => {
  clearRefreshCookie(res);
  return res.json({ ok: true });
});

// Example protected API (requires Authorization: Bearer <token>)
app.get('/api/profile', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'missing access token' });
  try {
    const decoded = jwt.verify(token, ACCESS_SECRET);
    res.json({ user: decoded });
  } catch (e) {
    res.status(401).json({ message: 'invalid token' });
  }
});

app.listen(PORT, () => {
  console.log(`Auth server listening on http://localhost:${PORT}`);
});
