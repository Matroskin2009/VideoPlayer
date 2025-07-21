import { mysqlTable, varchar, serial, boolean, timestamp } from 'drizzle-orm/mysql-core';

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