import express, { Request, Response } from 'express'
import { PassportStatic } from 'passport'
import jwt from 'jsonwebtoken'
import { register } from 'src/auth/controllers'
import tokensModule from 'src/auth/tokens'

const router = express.Router()

export default function (
  passport: PassportStatic,
  tokenSecret: jwt.Secret,
  updateOne: (where: Record<any, any>, updates: Record<any, any>) => any,
  findById: (id: string) => any,
  create: (newDate: any) => any,
) {
  const tokens = tokensModule({ tokenSecret, updateOne })

  /**
   * Validate Token
   */
  router.post(
    '/validate-token',
    tokens.authMiddleware(),
    async (req: Request, res: Response) => {
      if (res.locals?._id) {
        const user = findById(res.locals._id)
        delete (user as any).password
        return res.send(user)
      }
      res.send({ message: '404: User Not Found' }).status(404)
    },
  )

  /**
   * Login
   */
  router.post(
    '/login',
    passport.authenticate('local'),
    function (req: Request, res: Response) {
      res.send(req.user)
    },
  )

  /**
   * Register
   */
  router.post('/register', async (req: Request, res: Response) => {
    try {
      await register(
        {
          email: req.body.email,
          password: req.body.password,
        },
        create,
        tokenSecret,
        updateOne,
      )
      res.send('OK')
    } catch (err: any) {
      res.send(err.message)
    }
  })

  return router
}
