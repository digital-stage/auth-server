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

import * as express from 'express'
import * as cors from 'cors'
import * as https from 'https'
import * as fs from 'fs'
import * as path from 'path'
import * as mongoose from 'mongoose'
import * as passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local'
import { Strategy as JwtStrategy, VerifiedCallback, ExtractJwt } from 'passport-jwt'
import debug from 'debug'
import * as dotenv from 'dotenv'
import * as jwt from 'jsonwebtoken'
import { Request } from 'express'
import * as crypto from 'crypto'
import * as nodemailer from 'nodemailer'
import * as dotenvExpand from 'dotenv-expand'
import { BlacklistEntryModel } from './store/BlacklistEntryModel'
import { User, UserModel, UserType } from './store/UserModel'
import { ErrorCodes } from './errorCodes'
import { sendActivationLink, sendResetPasswordLink, getEnvPath } from './utils'

const inform = debug('auth')
const trace = inform.extend('trace')
const reportError = inform.extend('error')

const envPath = getEnvPath()
inform(`Loaded env from ${envPath}`)
const env = dotenv.config({ path: envPath })
dotenvExpand(env)

const smtpTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : undefined,
    secure: process.env.SMTP_SSL && process.env.SMTP_SSL === 'true',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
    },
})

const MONGOOSE_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:4321/auth'
const MONGOOSE_CA = process.env.MONGO_CA ? [fs.readFileSync(process.env.MONGO_CA)] : undefined
const PORT: number | string = process.env.PORT || 5000
const SECRET: string = process.env.SECRET || 'a2a4b644384b3c940ba4754a81736f79333077c8'

const app = express()
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(cors({ origin: true }))

app.options('*', cors())
app.use(passport.initialize())
app.use(passport.session())

passport.use(
    new LocalStrategy(
        {
            usernameField: 'email',
            passwordField: 'password',
        },
        (email, password, done) => {
            UserModel.findOne({ email })
                .exec()
                .then((user: UserType) => {
                    if (!user) {
                        trace(`Authentication failed, since no user exists with email ${email}`)
                        return done(null, false, { message: 'Invalid email/password' })
                    }
                    return user.validPassword(password).then((result) => {
                        if (!result) {
                            trace(
                                `Authentication failed due to an invalid password for email ${email}`
                            )
                            return done(null, false, { message: 'Invalid email/password' })
                        }
                        return done(null, user, { message: 'Logged in Successfully' })
                    })
                })
                .catch((e) => done(e))
        }
    )
)
passport.use(
    new JwtStrategy(
        {
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: SECRET,
            passReqToCallback: true,
        },
        (req: Request, jwt_payload: any, done: VerifiedCallback) => {
            // Check if token is blacklisted
            const token: string = ExtractJwt.fromAuthHeaderAsBearerToken()(req)
            BlacklistEntryModel.findOne({ token })
                .exec()
                .then((invalidToken) => {
                    if (invalidToken) {
                        return done(null, false)
                    }
                    return UserModel.findById(jwt_payload.user._id)
                        .exec()
                        .then((user) => {
                            if (user) {
                                return done(null, user)
                            }
                            return done(null, false)
                        })
                })
                .catch((err) => done(err, false))
        }
    )
)

const generateToken = (user: User) =>
    jwt.sign(
        {
            user: {
                _id: user._id,
                email: user.email,
            },
        },
        SECRET,
        {
            expiresIn: 604800,
        }
    )

app.get('/beat', (req, res) => {
    res.send('Hello World!')
})
app.post('/login', passport.authenticate('local', { session: false }), (req, res) => {
    const user: User = req.user as any
    if (user.active) {
        trace(`/login - generated token for ${user.name}`)
        return res.json(generateToken(user))
    }
    trace(`/login - cannot login inactive user ${user.name}`)
    return res.sendStatus(ErrorCodes.NotActivated)
})
app.get('/verify', passport.authenticate('jwt', { session: false }), (req, res) => {
    const user: User = req.user as any
    if (user) {
        if (user.active) {
            trace(`/profile - User ${user.name} is valid`)
            return res.sendStatus(200)
        }
        trace(`/verify - Send false for inactive user ${user.name}`)
        return res.sendStatus(ErrorCodes.NotActivated)
    }
    trace('/verify - Could not find user')
    return res.sendStatus(ErrorCodes.NotFound)
})
app.get('/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
    const user: User = req.user as any
    if (user) {
        if (user.active) {
            trace(`/profile - Sending profile of ${user.name}`)
            return res.json({
                _id: user._id,
                name: user.name,
                email: user.email,
                avatarUrl: user.avatarUrl,
            })
        }
        trace(`/profile - Do not return inactive profile for ${user.name}`)
        return res.sendStatus(ErrorCodes.NotActivated)
    }
    trace('/profile - Could not find profile')
    return res.sendStatus(ErrorCodes.NotFound)
})
app.post('/reactivate', (req, res) => {
    if (!req.body.email || typeof req.body.email !== 'string') {
        trace('/reactivate - Invalid request')
        return res.sendStatus(ErrorCodes.BadRequest)
    }
    UserModel.findOne({
        email: req.body.email,
    })
        .exec()
        .then((user) => {
            if (user) {
                if (!user.active) {
                    const activationCode: string = crypto.randomBytes(20).toString('hex')
                    /* eslint-disable no-param-reassign */
                    user.activationCode = activationCode
                    user.activationCodeExpires = Date.now() + 3600000
                    /* eslint-enable no-param-reassign */
                    return user
                        .save()
                        .then(() => sendActivationLink(smtpTransport, user.email, activationCode))
                        .then(() => trace(`/reactivate - Send activation code to ${user.name}`))
                        .then(() => res.sendStatus(200))
                        .catch((error: Error) => {
                            reportError(`/reactivate - ${error.toString()}`)
                            return res.sendStatus(ErrorCodes.InternalError)
                        })
                }
                trace(`/reactivate - User ${user.name} is already active`)
                return res.sendStatus(ErrorCodes.AlreadyActivated)
            }
            trace(`/reactivate - User not found by email ${req.body.email}`)
            return res.sendStatus(ErrorCodes.NotFound)
        })
        .catch((err: Error) => {
            reportError(`/reactivate - ${err.toString()}`)
            return res.sendStatus(ErrorCodes.InternalError)
        })
})
app.post('/activate', (req, res) => {
    if (!req.body.code || typeof req.body.code !== 'string') {
        trace('/activate - Invalid request')
        return res.sendStatus(ErrorCodes.BadRequest)
    }
    UserModel.findOne({
        activationCode: req.body.code,
        activationCodeExpires: { $gt: Date.now() },
    })
        .exec()
        .then((user) => {
            if (user) {
                if (!user.active) {
                    /* eslint-disable no-param-reassign */
                    user.active = true
                    user.activationCode = undefined
                    user.activationCodeExpires = undefined
                    /* eslint-enable no-param-reassign */
                    return user.save().then(() => {
                        trace(`/activate - Valid code used to activate ${user.name}`)
                        return res.sendStatus(200)
                    })
                }
                trace(`/activate - Account ${user.name} is already activated`)
            } else {
                trace('/activate - Invalid or expired code used to activate')
            }
            return res.sendStatus(ErrorCodes.InvalidToken)
        })
        .catch((err) => {
            reportError(`/activate - ${err}`)
            return res.sendStatus(ErrorCodes.InternalError)
        })
})
app.post('/token', passport.authenticate('local', { session: false }), (req, res) => {
    const user: User = req.user as any
    trace(`/token - generated token for user ${user.name}`)
    return res.json(generateToken(user))
})
app.post('/signup', (req, res) => {
    if (
        !req.body.name ||
        typeof req.body.name !== 'string' ||
        !req.body.password ||
        typeof req.body.password !== 'string' ||
        !req.body.email ||
        typeof req.body.email !== 'string' ||
        (req.body.avatarUrl && typeof req.body.avatarUrl !== 'string')
    ) {
        trace('/signup - Invalid request')
        return res.sendStatus(ErrorCodes.BadRequest)
    }
    UserModel.findOne({ email: req.body.email })
        .exec()
        .then((existingUser) => {
            if (existingUser) {
                trace(`/signup - Email address ${existingUser.email} already in use!`)
                return res.sendStatus(ErrorCodes.EmailAlreadyInUse)
            }
            const activationCode: string = crypto.randomBytes(20).toString('hex')
            const user = new UserModel()
            user.name = req.body.name
            user.password = req.body.password
            user.email = req.body.email
            user.avatarUrl = req.body.avatarUrl
            user.activationCode = activationCode
            user.activationCodeExpires = Date.now() + 3600000

            return user
                .save()
                .then(() => sendActivationLink(smtpTransport, user.email, activationCode))
                .then(() => trace(`/signup - Sent activation mail to ${user.email}`))
                .then(() => res.sendStatus(200))
        })
        .catch((err) => {
            reportError(`/signup - ${err}`)
            return res.sendStatus(ErrorCodes.InternalError)
        })
})
app.post('/logout', passport.authenticate('jwt', { session: false }), (req, res) => {
    const token: string = ExtractJwt.fromAuthHeaderAsBearerToken()(req)
    const invalidToken = new BlacklistEntryModel()
    invalidToken.token = token
    return invalidToken
        .save()
        .then(() => {
            trace(`/logout - Signed out user ${(req.user as any).name}`)
            trace(`/logout - Blacklisted token ${token}`)
            return res.sendStatus(200)
        })
        .catch((error) => {
            reportError(`/logout ${error}`)
            return res.sendStatus(ErrorCodes.InternalError)
        })
})
app.post('/forgot', (req, res) => {
    if (!req.body.email || typeof req.body.email !== 'string') {
        trace('/forgot - Invalid request')
        return res.sendStatus(ErrorCodes.BadRequest)
    }
    UserModel.findOne({ email: req.body.email })
        .exec()
        .then((user) => {
            if (user) {
                const resetToken: string = crypto.randomBytes(20).toString('hex')
                /* eslint-disable no-param-reassign */
                user.resetToken = resetToken
                user.resetPasswordExpires = Date.now() + 3600000
                /* eslint-enable no-param-reassign */
                return user
                    .save()
                    .then(() => sendResetPasswordLink(smtpTransport, user.email, resetToken))
                    .then(() => trace(`/forgot - Sent reset mail to ${user.email}`))
                    .then(() => res.sendStatus(200))
                    .catch((err) => {
                        reportError(err)
                        return res.sendStatus(ErrorCodes.InternalError)
                    })
            }
            trace(`/forgot - Could not found user by email ${req.body.email}`)
            return res.sendStatus(ErrorCodes.NotFound)
        })
        .catch((error) => {
            reportError(`/forgot ${error}`)
            return res.sendStatus(ErrorCodes.InternalError)
        })
})
app.post('/reset', (req, res) => {
    if (
        !req.body.password ||
        typeof req.body.password !== 'string' ||
        !req.body.token ||
        typeof req.body.token !== 'string'
    ) {
        trace('/reset - Invalid request')
        return res.sendStatus(ErrorCodes.BadRequest)
    }
    UserModel.findOne({
        resetToken: req.body.token,
        resetPasswordExpires: { $gt: Date.now() },
    })
        .then((user) => {
            if (user) {
                trace(`User ${user.name} reset password!`)
                /* eslint-disable no-param-reassign */
                user.password = req.body.password
                user.resetToken = undefined
                user.resetPasswordExpires = undefined
                /* eslint-enable no-param-reassign */

                return user.save().then(() => {
                    trace(`/reset - Successfully reset password of ${user.name}`)
                    return res.sendStatus(200)
                })
            }
            trace('/reset - Invalid token used for reset')
            return res.sendStatus(ErrorCodes.InvalidToken)
        })
        .catch((error) => {
            reportError(`/reset ${error}`)
            return res.sendStatus(ErrorCodes.InternalError)
        })
})

// INIT MONGOOSE
inform(`Connecting to ${MONGOOSE_URL} ...`)
mongoose
    .connect(MONGOOSE_URL, {
        sslValidate: !!MONGOOSE_CA,
        sslCA: MONGOOSE_CA,
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useFindAndModify: false,
        useCreateIndex: true,
    })
    .then(() => {
        inform(`Connected to ${MONGOOSE_URL}!`)
        if (!process.env.USE_SSL || process.env.USE_SSL === 'false') {
            app.listen(PORT)
            inform(`SERVER LISTENING WITHOUT SSL ON PORT ${PORT}`)
        } else {
            https.createServer({
                key: fs.readFileSync(path.resolve(process.env.SSL_KEY || './ssl/key.pem')),
                cert: fs.readFileSync(path.resolve(process.env.SSL_CRT || './ssl/cert.pem')),
                ca: process.env.SSL_CA
                    ? fs.readFileSync(path.resolve(process.env.SSL_CA))
                    : undefined,
                requestCert: true,
                rejectUnauthorized: false,
            })
            inform(`SERVER LISTENING WITH SSL ON PORT ${PORT}`)
        }
        return null
    })
    .catch((err) => reportError(err))
