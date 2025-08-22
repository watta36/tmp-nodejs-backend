import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const app = express();

// allow CORS from Angular frontend
const ALLOW_ORIGINS = [
  'http://localhost:4200',
  'https://tmp-angular-project.vercel.app',
];

app.use(cors({ origin: ALLOW_ORIGINS, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// mock user
const USERS = [{ id: 1, email: 'test@example.com', password: 'Passw0rd!', name: 'Tester' }];

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = USERS.find(u => u.email === email && u.password === password);

  if (!user) return res.status(401).json({ message: 'Invalid email or password' });

  const accessToken = 'fake-access-' + Date.now();
  const refreshToken = 'fake-refresh-' + Date.now();

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/api/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json({ accessToken, refreshToken, user: { id: user.id, email: user.email, name: user.name } });
});

app.post('/auth/refresh', (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ message: 'No refresh token' });
  res.json({ accessToken: 'new-access-' + Date.now() });
});

// 👇 สำคัญ ต้อง export default app
export default app;
