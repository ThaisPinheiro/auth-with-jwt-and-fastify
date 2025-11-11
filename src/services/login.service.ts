import { User } from '../model/user.model'
import bycript from 'bcrypt'
import jwt from 'jsonwebtoken'
import { AuthenticateInput } from '../insterfaces/auth.interface'
import { userBodySchema } from '../schemas/user.schema'

export class LoginService {
  async authenticateUser({ email, password }: AuthenticateInput) {
    const user = await User.findOne({ email })
    if (!user) throw new Error('Invalid credentials')

    const passwordMatch = bycript.compareSync(password, user.password)
    if (!passwordMatch) throw new Error('Invalid credentials')
    return user
  }

  async generateToken(user: { id?: string, role?: string }) {
    if (!!user.id) throw new Error('User id is required to generate token')
    const issuedAt = Math.floor(Date.now() / 1000)
    return jwt.sign(
            { sub: user.id, role: user.role, iat: issuedAt },
            process.env.JWT_SECRET!,
            { expiresIn: parseInt(process.env.JWT_EXPIRES || '1h') }
          )
  }
}