import { randomUUID } from 'node:crypto'
import { User } from '../model/user.model'
import { UserBodyInput } from '../insterfaces/user.interface'

export class UserService {
  async registerUser({ userName, email, password }: UserBodyInput) {
    const existingUser = await User.findOne({ email })
    if (existingUser) throw new Error('User invalid')

    const userId = randomUUID()
    const user = new User({
      userId, userName, email, password 
    })

    await user.save()
    return { userId, email, userName }
  }

  async getUserById(userId: string) {
    const user = await User.findOne({ userId })
    if (!user) throw new Error('User not found')
    return user
  }
}