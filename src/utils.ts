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

import * as Mail from 'nodemailer/lib/mailer'
import * as fs from 'fs'

const getEnvPath = (): string => {
    if (fs.existsSync('.env.local')) return '.env.local'
    if (fs.existsSync('.env')) return '.env'
    return `.env.${process.env.NODE_ENV}`
}

//const activationMail = fs.readFileSync('./templates/activate.html').toString()
//const resetPasswordMail = fs.readFileSync('./templates/reset.html').toString()

const sendActivationLink = (transport: Mail, email: string, code: string): Promise<any> =>
    transport.sendMail({
        to: email,
        from: process.env.SMTP_FROM,
        subject: 'Aktiviere Deinen Account',
        /*html: activationMail
    .replace('{url}', `${process.env.ACTIVATE_URL}?code=${code}`)
    .replace('{code}', code),*/
        text: `Du erhälst diese E-Mail da Du (oder jemand anderes) einen Account auf digital-stage.org erstellt hat.\n\nDein Aktivierungscode lautet:\n${code}\n\nBitte klicke auf den folgenden Link, um Deinen Account zu aktivieren:\n${process.env.ACTIVATE_URL}?code=${code}\n\nFalls Du keinen Account erstellt hast, ignoriere einfach diese E-Mail.\n`,
    })

const sendResetPasswordLink = (transport: Mail, email: string, code: string): Promise<any> =>
    transport.sendMail({
        to: email,
        from: process.env.SMTP_FROM,
        subject: 'Passwort zurücksetzen',
        /*html: resetPasswordMail
    .replace('{url}', `${process.env.ACTIVATE_URL}?code=${code}`)
    .replace('{code}', code),*/
        text: `Du erhälst diese E-Mail da Du (oder jemand anderes) dein Passwort auf digital-stage.org zurücksetzen möchte.\n\nBitte klicke auf den folgenden Link, um Dein Passwort zurückzusetzen:\n\n${process.env.RESET_URL}?token=${code}\n\nFalls Du nicht Dein Passwort zurücksetzen wolltest, ignoriere bitte diese E-Mail.\n`,
    })
export { sendActivationLink, sendResetPasswordLink, getEnvPath }
