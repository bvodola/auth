import jwt from 'jsonwebtoken'
import { Request, Response, NextFunction } from 'express'

export default function ({
  tokenSecret,
  updateOne,
}: {
  tokenSecret: jwt.Secret
  updateOne: (where: Record<any, any>, updates: Record<any, any>) => any
}) {
  function generate(data: any) {
    return new Promise((resolve, reject) => {
      jwt.sign(
        data,
        process.env.TOKEN_SECRET as jwt.Secret,
        {},
        function (err, token) {
          if (err) reject(err)
          else {
            resolve(token)
          }
        },
      )
    })
  }

  function save(user: any, token: string) {
    return new Promise(async (resolve, reject) => {
      // Update user with token
      await updateOne({ _id: user._id }, { token })
      resolve({ ...user, token })
    })
  }

  function validate(token: string): any {
    return new Promise((resolve, reject) => {
      jwt.verify(token, tokenSecret, function (err, data) {
        if (err) reject(err)
        else resolve(data)
      })
    })
  }

  const authMiddleware =
    (config: { bypass?: (req: Request) => boolean } = {}) =>
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!config.bypass) config.bypass = () => false
        if (config.bypass(req) === true) return next()
        if (req.method == 'OPTIONS') return res.sendStatus(200)
        if (typeof req.headers.authorization === 'undefined')
          return res.sendStatus(401)

        const token = String(req.headers.authorization).split('Bearer ')[1]
        const tokenData = await validate(token)
        if (tokenData === 'undefined') res.sendStatus(401)

        res.locals.user_id = tokenData.id
        return next()
      } catch (err) {
        res.status(401).send(err)
      }
    }

  return {
    generate,
    save,
    validate,
    authMiddleware,
  }
}
