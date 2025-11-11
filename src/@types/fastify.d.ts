import 'fastify'
import winston from 'winston'

declare module 'fastify' {
  interface FastifyInstance {
    logger: winston.Logger
  }

  interface FastifyRequest {
    user?: any
  }

  interface FastifyInstance {
    verifyJWT: (request: FastifyRequest, reply: FastifyReply) => Promise<void>
    authorizeRole: (role: string) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>
  }
}