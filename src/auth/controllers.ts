import bcrypt from 'bcryptjs'
import tokensModule from 'src/auth/tokens'
import jwt from 'jsonwebtoken'

export type CreateUserDto = {
  email: string
  password: string
}

export function register(
  newUser: CreateUserDto,
  create: (newDate: any) => any,
  tokenSecret: jwt.Secret,
  updateOne: (where: Record<any, any>, updates: Record<any, any>) => any,
) {
  const tokens = tokensModule({ tokenSecret, updateOne })

  return new Promise(async (resolve, reject) => {
    try {
      if (!newUser.email || !newUser.password) {
        throw new Error('Invalid user email or password')
      }

      if (typeof newUser.password !== 'undefined') {
        newUser.password = bcrypt.hashSync(
          newUser.password,
          bcrypt.genSaltSync(8),
        )
      }

      const user = await create({ ...newUser })
      const token = await tokens.generate({ _id: user._id })
      console.log(token)
      const updateRes = await updateOne({ _id: user._id }, { $set: { token } })
      console.log(updateRes)

      resolve('User created')
    } catch (err) {
      console.log(err)
      reject(err)
    }
  })
}
