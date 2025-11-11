import mongoose from 'mongoose'
import { TokenBlacklist } from '../insterfaces/token-blacklist.interface'


const blacklistSchema = new mongoose.Schema<TokenBlacklist>({
  token: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
})
blacklistSchema.set('capped', { size: 1024 * 1024, max: 1000, autoIndexId: true }); //1MB

export const TokenBlacklistModel = mongoose.model<TokenBlacklist>(
  'TokenBlacklist', blacklistSchema, 'token_blacklist'
)