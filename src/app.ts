import fastify from 'fastify'
import loggerPlugin from './plugins/logger.plugin'
import { indexRoutes } from './routes/index.route'
import authCheckerPlugin from './plugins/auth-checker.plugin'

export const app = fastify({
   bodyLimit: 1048576, // 1MB
})

app.register(authCheckerPlugin)
app.register(loggerPlugin)
indexRoutes(app)