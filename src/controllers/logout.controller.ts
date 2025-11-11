import { FastifyReply, FastifyRequest } from 'fastify'
import { LogoutService } from '../services/logout.service'

export class LogoutController {
  constructor(private service: LogoutService) {}

  logout = async (request: FastifyRequest, reply: FastifyReply) => {
    const authHeader = request.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.status(401).send({ error: 'Unauthorized' })
    }

    try {
    const token = authHeader.split(' ')[1]
      await this.service.logout({
        token,
        userId: request.user.id,
        logger: request.log
      })
      return reply.status(200).send({ message: 'Successfully logged out' })
    } catch (error) {
      return reply.status(500).send({ error: 'Internal Server Error' })
    }
  }
}