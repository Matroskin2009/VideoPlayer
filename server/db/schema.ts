import { mysqlTable, varchar, serial, boolean, timestamp, int, text } from 'drizzle-orm/mysql-core';

export const users = mysqlTable('users', {
  id: serial('id').primaryKey(),
  google_id: varchar('google_id', { length: 255 }).notNull(),
  email: varchar('email', { length: 255 }).notNull(),
  username: varchar('username', { length: 255 }).notNull().unique(),
  password_hash: varchar('password_hash', {length: 256}),
  email_verification_token: varchar('email_verification_token', { length: 256 }),
  email_verified: boolean('email_verified').default(false).notNull(),
  email_verification_expires: timestamp('email_verification_expires', { mode: 'date' }),
  avatar_url: varchar('avatar_url', { length: 255 }),
});

export const likes = mysqlTable('likes', {
  user_id: int('user_id').notNull(),
  video_id: int('video_id').notNull(),
});


export const subscriptions = mysqlTable('subscriptions', {
  subscriber_id: int('subscriber_id').notNull(),
  target_id: int('target_id').notNull(),
});

export const videos = mysqlTable('videos', {
  id: serial('id').primaryKey(),
  user_id: int('user_id').notNull(),
  title: varchar('title', { length: 100 }).notNull(),
  description: text('description'),
  url: varchar('url', { length: 255 }).notNull(),
  thumbnail_url: varchar('thumbnail_url', { length: 255 }),
  views: int('views').default(0),
});