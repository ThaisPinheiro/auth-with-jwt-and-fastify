import { FastifyReply, FastifyRequest } from "fastify"
import { userBodySchema } from "../schemas/user.schema"
import { UserService } from "../services/user.service"

export class UserController {
  constructor(private service: UserService) {}

  register = async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const userData = userBodySchema.parse(request.body)
      const user = await this.service.registerUser(userData)
      request.log.info(`User created: { id: ${user.userId}, timestamp: ${new Date().toISOString()} }`)
      return reply.status(201).send({ message: 'User registered successfully' })
    } catch (error: any) {
      request.log.error(`User registration failed: ${error?.message ?? 'unknown error'}`)
      return reply.status(400).send({ error: error.message })
    }
  }

  getUserAccount = async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const userId = request.user.id
      const user = await this.service.getUserById(userId)
      return reply.send(user)
    } catch (error: any) {
      request.log.error(`Failed to get user account: ${error?.message ?? 'unknown error'}`)
      return reply.status(500).send({ error: 'Internal Server Error' })
    }
  }
}