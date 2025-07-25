import 'dotenv/config';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { cors } from 'hono/cors';
import { OAuth2Client } from 'google-auth-library';
import { db } from './db/index';
import { users } from './db/schema';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { sendVerificationEmail } from './lib/email.js';
import crypto from 'crypto';
import { eq, sql, and } from 'drizzle-orm';
import { likes, subscriptions, videos } from './db/schema';

const app = new Hono();

app.use('*', cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));

//подключение клиента
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: 'http://localhost:3001/auth/google/callback',
});

//переброс на гугл регистрацию с просьбой получить scope
app.get('/auth/google', (c) => {
  const url = googleClient.generateAuthUrl({
    scope: ['email', 'profile'],
  });
  return c.redirect(url);
});

app.get('/auth/google/callback', async (c) => {
  const { code } = c.req.query();
  const { tokens } = await googleClient.getToken(code);
  const ticket = await googleClient.verifyIdToken({
    idToken: tokens.id_token!,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const { sub, email, name, picture } = ticket.getPayload()!;

  let user = await db.query.users.findFirst({
    where: (users, { eq }) => eq(users.google_id, sub),
  });

  if (!user) {
    // Если пользователя с таким google_id нет, ищем по email
    user = await db.query.users.findFirst({
      where: (users, { eq }) => eq(users.email, email!),
    });

    if (user) {
      // Если пользователь с таким email уже есть, просто обновляем google_id
      await db.update(users).set({
        google_id: sub,
        avatar_url: picture || '/default-avatar.jpg',
      }).where(eq(users.id, user.id));
    } else {
      // Если вообще нет — создаём нового
      await db.insert(users).values({
        google_id: sub,
        email: email!,
        username: name || email?.split('@')[0] || 'user',
        password_hash: '',
        avatar_url: picture || '/default-avatar.jpg',
      });
      user = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.google_id, sub),
      });
    }
  }

  const sessionId = crypto.randomUUID();
  sessions[sessionId] = { userId: user.id };
  setCookie(c, 'session_id', sessionId, {
    httpOnly: true,
    secure: false,
    sameSite: 'Lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });

  return c.redirect('http://localhost:3000');
});

const sessions: Record<string, { userId: number }> = {};

const registerSchema = z.object({
  username: z.string().min(1, "Имя пользователя не может быть пустое"),
  email: z.string().email("Некорректный email"),
  password: z.string().min(6, "Пароль должен быть не короче 6 символов"),
});

app.post('/api/auth/register', zValidator('json', registerSchema), async (c) => {
  const { username, email, password } = c.req.valid('json');

  const existingUser = await db.query.users.findFirst({
    where: (users, { eq, and }) => and(
      eq(users.email, email),
      eq(users.email_verified, true)
    ),
  });

  if (existingUser) {
    return c.json({ error: 'Пользователь с таким email уже существует' }, 409);
  }

  const saltRounds = 10;
  const password_hash = await bcrypt.hash(password, saltRounds);

  const verificationToken = crypto.randomBytes(32).toString('hex');
  const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  const unverifiedUser = await db.query.users.findFirst({
      where: (users, { eq }) => eq(users.email, email)
  });

  if (unverifiedUser) {
    await db.update(users).set({
      username,
      password_hash,
      email_verification_token: verificationToken,
      email_verification_expires: verificationTokenExpires,
    }).where(eq(users.id, unverifiedUser.id));
  } else {
    await db.insert(users).values({
      email,
      username,
      password_hash,
      google_id: `classic_${Date.now()}`,
      email_verification_token: verificationToken,
      email_verification_expires: verificationTokenExpires,
    });
  }

  try {
    await sendVerificationEmail(email, verificationToken);
    return c.json({ message: 'Письмо с подтверждением отправлено на ваш email.' });
  } catch (error) {
    console.error("Ошибка отправки email:", error);
    return c.json({ error: 'Не удалось отправить письмо с подтверждением.' }, 500);
  }
});

const loginSchema = z.object({
  email: z.string().email("Некорректный email"),
  password: z.string().min(6, "Пароль должен быть не короче 6 символов"),
});

app.post('/api/auth/login', zValidator('json', loginSchema), async (c) => {
  const { email, password } = c.req.valid('json');

  const user = await db.query.users.findFirst({
    where: (users, { eq }) => eq(users.email, email),
  });

  if (!user) {
    return c.json({ error: 'Неправильный email или пароль' }, 401);
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash || '');
  if (!isPasswordValid) {
    return c.json({ error: 'Неправильный email или пароль' }, 401);
  }

  const sessionId = crypto.randomUUID();
  sessions[sessionId] = { userId: user.id };

  setCookie(c, 'session_id', sessionId, {
    httpOnly: true,
    secure: false,
    sameSite: 'Lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });

  return c.json({ message: 'Вход выполнен успешно' });
});

app.get('/api/auth/me', async (c) => {
  const sessionId = getCookie(c, 'session_id');
  if (!sessionId || !sessions[sessionId]) {
    return c.json({ user: null }, 401);
  }

  const user = await db.query.users.findFirst({
    where: (users, { eq }) => eq(users.id, sessions[sessionId].userId),
    columns: {
      id: true,
      username: true,
      email: true,
      avatar_url: true,
    }
  });

  if (!user) {
    delete sessions[sessionId];
    deleteCookie(c, 'session_id');
    return c.json({ user: null }, 401);
  }

  const subscribersCount = await db.select({
    count: sql<number>`count(*)`
  }).from(subscriptions).where(eq(subscriptions.target_id, user.id));

  const userVideos = await db.select({
    id: videos.id
  }).from(videos).where(eq(videos.user_id, user.id));

  const videoIds = userVideos.map(v => v.id);

  let likesCount = [{ count: 0 }];
  if (videoIds.length > 0) {
    likesCount = await db.select({
      count: sql<number>`count(*)`
    }).from(likes).where(and(eq(likes.user_id, user.id), sql`video_id IN ${videoIds}`));
  }

  return c.json({
    user: {
      ...user,
      subscribers: subscribersCount[0].count,
      likes: likesCount[0].count,
    }
  });
});

app.post('/api/auth/logout', async (c) => {
  const sessionId = getCookie(c, 'session_id');

  if (sessionId) {
    delete sessions[sessionId];
  }

  deleteCookie(c, 'session_id', {
    path: '/',
    domain: 'localhost',
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax',
    httpOnly: true
  });

  return c.json({ message: 'Выход выполнен успешно' });
});


serve({ fetch: app.fetch, port: 3001 }, (info) => {
  console.log(`Listening on http://localhost:${info.port}`);
});


app.get('/api/auth/verify-email', async (c) => {
  const token = c.req.query('token');

  if (!token) {
    return c.text('Токен верификации отсутствует.', 400);
  }

  const user = await db.query.users.findFirst({
    where: (users, { eq, and, gte }) => and(
      eq(users.email_verification_token, token),
      gte(users.email_verification_expires, new Date())
    ),
  });

  if (!user) {
    return c.text('Неверный или просроченный токен верификации.', 400);
  }

  await db.update(users).set({
    email_verified: true,
    email_verification_token: null,
    email_verification_expires: null,
  }).where(eq(users.id, user.id));

  return c.redirect('http://localhost:3000/login?verified=true');
});