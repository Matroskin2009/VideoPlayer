
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function POST() {
  cookies().delete('session_id');

  return NextResponse.json({ message: 'Выход выполнен успешно' });
}