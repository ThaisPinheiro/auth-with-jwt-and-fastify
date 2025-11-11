import { FastifyReply, FastifyRequest } from 'fastify'
import { loginBodySchema } from '../schemas/login.schema'
import { LoginService } from '../services/login.service'

export class LoginController {
  constructor(private service: LoginService) {}

  login = async (request: FastifyRequest, reply: FastifyReply) => {
    const loginData = loginBodySchema.parse(request.body)
    const user = await this.service.authenticateUser(loginData)

    try {
      const token = this.service.generateToken(user)
      return reply.status(200).send({ token })
    } catch (error: any) {
      request.log.error(`Token non generated for the user: { id: ${user.id}, timestamp: ${new Date().toISOString()} }`)
      return reply.status(500).send({ error: error.message })
    }
  }
}