import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { UserService } from '../services/user.service'
import { UserController } from '../controllers/user.controller'

export async function userRoutes(app: FastifyInstance) {
  const service = new UserService()
  const controller = new UserController(service)

  app.post('/register', controller.register)

  app.get('/admin',
    { preHandler: [app.verifyJWT, app.authorizeRole('admin')] },
    async () => ({ message: 'Welcome, admin!'}))

  app.get('/my-account', {preHandler: [app.verifyJWT]}, controller.getUserAccount)

  app.get('/home', {preHandler: [app.verifyJWT]},
    async () => ({ message: 'Welcome to the home page!' }))
}