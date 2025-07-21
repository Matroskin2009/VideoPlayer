import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendVerificationEmail(to: string, token: string) {
  const verificationUrl = `http://localhost:3000/verify-email?token=${token}`;

  try {
    const { data, error } = await resend.emails.send({
      from: 'VideoPlayer <onboarding@resend.dev>', 
      to: [to],
      subject: 'Подтвердите ваш Email для VideoPlayer',
      html: `
        <h1>Подтверждение Email</h1>
        <p>Спасибо за регистрацию в VideoPlayer. Пожалуйста, кликните по ссылке ниже, чтобы подтвердить ваш email:</p>
        <a href="${verificationUrl}">${verificationUrl}</a>
      `,
    });

    if (error) {
      throw error;
    }

    console.log('Verification email sent:', data);
    
  } catch (error) {
    console.error("Ошибка отправки email через Resend:", error);
    throw new Error('Не удалось отправить письмо с подтверждением.');
  }
}