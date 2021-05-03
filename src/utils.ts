import * as Mail from 'nodemailer/lib/mailer'
import * as fs from 'fs'

const getEnvPath = () => {
    if (fs.existsSync('.env.local')) return '.env.local'
    if (fs.existsSync('.env')) return '.env'
    if (fs.existsSync(`.env.${process.env.NODE_ENV}`)) return `.env.${process.env.NODE_ENV}`
    throw new Error(
        `No environmental file (.env.local, .env or .env.${process.env.NODE_ENV}) provided!`
    )
}

const sendActivationLink = (transport: Mail, email: string, code: string) =>
    transport.sendMail({
        to: email,
        from: process.env.SMTP_FROM,
        subject: 'Aktiviere Deinen Account',
        text:
            `${
                'Du erhälst diese E-Mail da Du (oder jemand anderes) einen Account auf digital-stage.org erstellt hat.\n\n' +
                'Bitte klicke auf den folgenden Link, um Deinen Account zu aktivieren:\n\n'
            }${process.env.ACTIVATE_URL}?code=${code}\n\n` +
            'Falls Du keinen Account erstellt hast, ignoriere einfach diese E-Mail.\n',
    })

const sendResetPasswordLink = (transport: Mail, email: string, code: string) =>
    transport.sendMail({
        to: email,
        from: process.env.SMTP_FROM,
        subject: 'Passwort zurücksetzen',
        text:
            `${
                'Du erhälst diese E-Mail da Du (oder jemand anderes) dein Passwort auf digital-stage.org zurücksetzen möchte.\n\n' +
                'Bitte klicke auf den folgenden Link, um Dein Passwort zurückzusetzen:\n\n'
            }${process.env.RESET_URL}?token=${code}\n\n` +
            'Falls Du nicht Dein Passwort zurücksetzen wolltest, ignoriere bitte diese E-Mail.\n',
    })
export { sendActivationLink, sendResetPasswordLink, getEnvPath }
