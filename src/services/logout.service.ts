import { TokenBlacklistModel } from "../model/token-blacklist.model";

export class LogoutService {
  async logout(payload: LogoutPayload) {
    try {
      await TokenBlacklistModel.create({ token: payload.token })
      payload.logger.info({
        action: 'Logout',
        user: payload.userId,
        timestamp: new Date().toISOString()
      })
    } catch (error) {
      payload.logger.error({ error, action: 'Logout', user: payload.userId })
      throw new Error('Failed to logout user')
    }
  }
}