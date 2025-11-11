import { z } from 'zod'
import { validatePassword, validatePasswordCharacters } from '../helpers/password.helper'
import { UserBodyInput } from '../insterfaces/user.interface'

export const userBodySchema = z.object({
  userName: z.string().min(5).max(20).trim().toLowerCase(),
  email: z.string().email().toLowerCase().trim(),
  password: validatePasswordCharacters(),
  role: z.string().min(4).max(20).trim().toLowerCase(),
})
.superRefine(({ userName, email, password }: UserBodyInput, ctx) => {
  validatePassword(password, userName, email).forEach((error) => {
    ctx.addIssue({
      code: "custom",
      path: ['password'],
      message: 'Senha contém muitos caracteres repetidos',
    })
  })
})