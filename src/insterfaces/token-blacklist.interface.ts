export interface TokenBlacklist extends Document {
  token: string
  createdAt: Date
}