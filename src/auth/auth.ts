import passport from 'passport'
import { Application } from 'express'
import session from 'cookie-session'
import jwt from 'jsonwebtoken'
import tokens from './tokens'
import authRoutes from './routes'
import passportStrategies from './strategies'

export default function ({
  app,
  tokenSecret,
  passportSecret,
  updateOne,
  findById,
  findOne,
  create,
}: {
  app: Application
  tokenSecret: jwt.Secret
  passportSecret: string
  updateOne: (where: Record<any, any>, updates: Record<any, any>) => any
  findById: (id: string | number) => any
  findOne: (where: any) => any
  create: (newDate: any) => any
}) {
  const authTokens = tokens({ tokenSecret, updateOne })

  app.use(session({ secret: passportSecret }))
  app.use(passport.initialize())
  passportStrategies(passport, findById, findOne)
  app.use(
    '/auth',
    authRoutes(passport, tokenSecret, updateOne, findById, create),
  )

  return {
    authMiddleware: authTokens.authMiddleware,
  }
}
