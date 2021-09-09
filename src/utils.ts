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
