import fp from 'fastify-plugin'
import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import jwt from 'jsonwebtoken'
import { TokenBlacklistModel } from '../model/token-blacklist.model'

export default fp(async function authChecker(app: FastifyInstance) {
  const secret = process.env.JWT_SECRET
  if (!secret) throw new Error('JWT_SECRET is not defined')

  app.decorate('verifyJWT', async function(request: FastifyRequest, reply: FastifyReply) {
    try {
      const authHeader = request.headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return reply.code(401).send({ error: 'Unauthorized' })
      }

      const token = authHeader.split(' ')[1]
      if (!token) {
        return reply.code(401).send({ error: 'Unauthorized' })
      }

      const isBlacklisted = await TokenBlacklistModel.exists({ token })
      if (isBlacklisted) {
        return reply.code(401).send({ error: 'Token invalidated. Please login again.' })
      }

      const decoded = jwt.verify(token, secret)
      if (!decoded) {
        return reply.code(403).send({ error: 'Forbidden' })
      }

      request.user = decoded
    } catch (error) {
      request.log.error({ err: error }, 'Unexpected JWT verification error')
      return reply.code(500).send({ error: 'Invalid token' })
    }
  })

  app.decorate('authorizeRole', (role: string) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      const userRole = request.user?.role
      if (!userRole) return reply.code(403).send({ error: 'Forbidden' })
      if (userRole !== role) return reply.code(403).send({ error: 'Forbidden' })
    }
  })
})