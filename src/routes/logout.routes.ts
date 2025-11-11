import { FastifyInstance } from 'fastify'
import { LogoutService } from '../services/logout.service'
import { LogoutController } from '../controllers/logout.controller'

export async function logoutRoutes(app: FastifyInstance) {
  const service = new LogoutService()
  const controller = new LogoutController(service)

  app.post('/', { preHandler: [app.verifyJWT] }, controller.logout)
}