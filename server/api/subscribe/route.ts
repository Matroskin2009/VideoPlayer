// app/api/subscribe/route.ts
import { Hono } from 'hono'
import { getAuth } from '@hono/nextjs-auth'
import { db } from '../../../../server/db/index'

const app = new Hono()

app.post('api/subscribe', async (c) => {
  try {
    const auth = getAuth(c)
    if (!auth.userId) {
      return c.json({ error: 'Unauthorized' }, 401)
    }

    const { user_id } = await c.req.json()

    const existingSub = await db.subscription.findFirst({
      where: {
        userId: user_id,
        subscriberId: auth.userId
      }
    })

    if (existingSub) {
      await db.subscription.delete({
        where: { id: existingSub.id }
      })

      const updatedUser = await db.user.update({
        where: { id: user_id },
        data: { subscribersCount: { decrement: 1 } },
        select: { subscribersCount: true }
      })

      return c.json({
        success: true,
        isSubscribed: false,
        subscribersCount: updatedUser.subscribersCount
      })
    } else {
      await db.subscription.create({
        data: {
          userId: user_id,
          subscriberId: auth.userId
        }
      })

      const updatedUser = await db.user.update({
        where: { id: user_id },
        data: { subscribersCount: { increment: 1 } },
        select: { subscribersCount: true }
      })

      return c.json({
        success: true,
        isSubscribed: true,
        subscribersCount: updatedUser.subscribersCount
      })
    }
  } catch (error) {
    console.error('Subscription error:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default app