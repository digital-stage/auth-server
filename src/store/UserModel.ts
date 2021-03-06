import * as mongoose from 'mongoose'
import * as bcrypt from 'bcrypt'

export interface User {
    _id: string
    name: string
    email: string
    password?: string
    passwordHash: string
    avatarUrl: string
    active: boolean
    activationCode?: string
    activationCodeExpires?: number
    resetToken?: string
    resetPasswordExpires?: number
}

const UserSchema = new mongoose.Schema(
    {
        name: { type: String, required: true },
        email: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },
        passwordHash: { type: String, required: true },
        avatarUrl: { type: String },
        active: { type: Boolean },
        activationCode: { type: String },
        activationCodeExpires: { type: Number },
        resetToken: { type: String },
        resetPasswordExpires: { type: Number },
    },
    { timestamps: true }
)

function validPassword(password): Promise<boolean> {
    return bcrypt.compare(password, this.passwordHash.toString())
}

UserSchema.methods.validPassword = validPassword

function hashPassword(value) {
    this.passwordHash = bcrypt.hashSync(value, 12)
}

UserSchema.virtual('password').set(hashPassword)
export type UserType = User &
    mongoose.Document & {
        validPassword(password: string): Promise<boolean>
    }
export const UserModel = mongoose.model<UserType>('User', UserSchema)
