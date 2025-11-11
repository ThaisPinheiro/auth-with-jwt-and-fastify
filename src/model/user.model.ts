import mongoose from 'mongoose'
import bcrypt from "bcrypt"

const userSchema = new mongoose.Schema({
  userName: { type: String, required: true, minlength: 5, unique: true },
  email: { type: String, required: true, match: /.+\@.+\..+/, unique: true },
  password: { type: String, required: true, minlength: 8, select: false },
  role:{ type: String, required: true, minlength: 4, default: 'user', enum: ['user', 'admin', 'manager'] },
  createdAt: { type: Date, default: Date.now },
  updateAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function (next) {
  if (this.isModified('password') || this.isNew) {
    const salt = await bcrypt.genSalt(10)
    this.password = await bcrypt.hash(this.password, salt)
  }
  next()
})

export const User = mongoose.model('User', userSchema)