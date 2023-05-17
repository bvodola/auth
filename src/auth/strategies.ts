import bcrypt from 'bcryptjs'
import { PassportStatic } from 'passport'

var LocalStrategy = require('passport-local').Strategy

// ====
// Auth
// ====

export default function (
  passport: PassportStatic,
  findById: (id: string | number) => any,
  findOne: (where: any) => any,
) {
  passport.serializeUser(function (user, done) {
    done(null, (user as any).id)
  })

  passport.deserializeUser(async function (id: number, done) {
    try {
      const user = findById(id)
      done(null, user)
    } catch (err) {
      done(err)
    }
  })

  // =====
  // Local
  // =====
  passport.use(
    new LocalStrategy(
      {
        usernameField: 'email',
      },
      async function (email: string, password: string, done: any) {
        try {
          const user = await findOne({ email })
          if (!user)
            return done(null, false, { message: 'Incorrect username.' })

          const isPasswordCorrect = bcrypt.compareSync(password, user?.password)
          if (!isPasswordCorrect)
            return done(null, false, { message: 'Incorrect password.' })

          return done(null, user)
        } catch (err) {
          return done(err)
        }
      },
    ),
  )
}
