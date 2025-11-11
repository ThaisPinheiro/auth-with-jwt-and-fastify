import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { LoginService } from '../services/login.service'
import { LoginController } from '../controllers/login.controller'

export async function loginRoutes(app: FastifyInstance) {
  const service = new LoginService()
  const controller = new LoginController(service)

  app.post('/login', controller.login)
}