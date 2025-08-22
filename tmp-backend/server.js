import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// CORS setup
app.use(cors({
  origin: [
    'http://localhost:4200',                        // dev frontend
    'https://tmp-angular-project.vercel.app'        // vercel frontend
  ],
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());

// mock users
const USERS = [{ id: 1, email: 'test@example.com', password: '123456', name: 'Tester' }];

// login route
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = USERS.find(u => u.email === email && u.password === password);

  if (!user) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  // mock tokens
  const accessToken = 'fake-access-token-' + Date.now();
  const refreshToken = 'fake-refresh-token-' + Date.now();

  // send refresh token in cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/api/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json({
    accessToken,
    refreshToken,
    user: { id: user.id, email: user.email, name: user.name },
  });
});

// refresh token
app.post('/api/auth/refresh', (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token' });
  }

  const newAccessToken = 'new-access-token-' + Date.now();
  res.json({ accessToken: newAccessToken });
});

// health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Backend running on http://localhost:${port}`));
