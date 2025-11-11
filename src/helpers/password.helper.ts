import { z } from 'zod'

export function validatePasswordCharacters() {
  return z.string().min(8).regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+\=\[\]{};:'",.<>\/?\\|`~]).+$/,
    "Senha deve conter pelo menos 1 letra maiúscula, 1 letra minúscula, 1 número e 1 caractere especial"
  )
}

export function validatePassword(password: string, userName: string, email: string): string[] {
  const errors: string[] = []
  const lowerPwd = password.toLowerCase()

  if (lowerPwd.includes(userName) || (userName && lowerPwd.includes(userName.replace(/\s+/g, '')))) {
    errors.push('Senha não pode conter o nome de usuário')
  }

  if (email && lowerPwd.includes(email.split('@')[0])) {
    errors.push('Senha não pode conter parte do email')
  }

  if (/(.)\1{3,}/.test(password)) {
    errors.push('Senha contém muitos caracteres repetidos')
  }

  return errors
}