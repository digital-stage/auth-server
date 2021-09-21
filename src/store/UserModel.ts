/*
 * Copyright (c) 2021 Tobias Hegemann
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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

    canCreateStage: boolean
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

        canCreateStage: { type: Boolean },
    },
    { timestamps: true }
)

function validPassword(password): Promise<boolean> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    return bcrypt.compare(password, this.passwordHash.toString())
}

UserSchema.methods.validPassword = validPassword

function hashPassword(value) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    this.passwordHash = bcrypt.hashSync(value, 12)
}

UserSchema.virtual('password').set(hashPassword)
export type UserType = User &
    mongoose.Document & {
        validPassword(password: string): Promise<boolean>
    }
export const UserModel = mongoose.model<UserType>('User', UserSchema)
