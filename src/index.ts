import * as pino from "pino";
import * as express from "express";
import * as cors from "cors";
import * as https from "https";
import * as fs from "fs";
import * as path from "path";
import * as core from "express-serve-static-core";
import * as mongoose from "mongoose";
import * as passport from "passport";
import * as LocalStrategy from "passport-local";
import {Strategy as JwtStrategy, VerifiedCallback} from "passport-jwt";
import {ExtractJwt} from "passport-jwt";
import {User, UserModel, UserType} from "./store/UserModel";
import * as jwt from "jsonwebtoken";
import {BlacklistEntryModel} from "./store/BlacklistEntryModel";
import {Request} from "express";
import * as crypto from "crypto";
import * as nodemailer from "nodemailer";
import {resolveVariables} from "./env";

resolveVariables();

const MONGOOSE_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:4321/auth";
export const PORT: number | string = process.env.PORT || 5000;
const SECRET: string = process.env.SECRET || "a2a4b644384b3c940ba4754a81736f79333077c8";
const logger = pino({
    level: process.env.LOG_LEVEL || 'info'
});

// INIT MONGOOSE
mongoose.connect(MONGOOSE_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false
}).then()

const app: core.Express = express();
app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.use(cors({origin: true}));

app.options('*', cors());
app.use(passport.initialize());
app.use(passport.session());

const smtpTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : undefined,
    secure: process.env.SMTP_SSL && process.env.SMTP_SSL === "true",
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
    }
});

passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    },
    function (email, password, done) {
        UserModel.findOne({email: email}).exec()
            .then((user: UserType) => {
                if (!user) {
                    logger.debug("Authentication failed, since no user exists with email " + email);
                    return done(null, false, {message: "Invalid email/password"});
                } else {
                    return user.validPassword(password)
                        .then(result => {
                            if (!result) {
                                logger.debug("Authentication failed due to an invalid password for email " + email);
                                return done(null, false, {message: "Invalid email/password"});
                            }
                            return done(null, user, {message: 'Logged in Successfully'});
                        })
                }
            })
            .catch(e => done(e));
    }
));
passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: SECRET,
    passReqToCallback: true
}, function (req: Request, jwt_payload: any, done: VerifiedCallback) {
    // Check if token is blacklisted
    const token: string = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
    return BlacklistEntryModel.findOne({token: token}).exec()
        .then(invalidToken => {
            if (invalidToken) {
                return done(null, false);
            }
            return UserModel.findById(jwt_payload.user._id).exec()
                .then(user => {
                    if (user) {
                        return done(null, user);
                    }
                    return done(null, false);
                })
                .catch(err => done(err, false));
        })
}));

const generateToken = (user: User) => {
    return jwt.sign({
        user: {
            _id: user._id,
            email: user.email
        }
    }, SECRET, {
        expiresIn: 604800
    });
}

app.get('/', function (req, res) {
    res.send('Hello World!');
});
app.post('/login',
    passport.authenticate('local', {session: false}),
    function (req, res) {
        const user: User = req.user as any;
        return res.json(generateToken(user));
    }
);
app.get('/verify',
    passport.authenticate('jwt', {session: false}),
    function (req, res) {
        const user: User = req.user as any;
        if (user) {
            return res.sendStatus(200);
        }
        return res.sendStatus(401);
    }
);
app.get('/profile',
    passport.authenticate('jwt', {session: false}),
    function (req, res) {
        const user: User = req.user as any;
        return res.status(200).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            avatarUrl: user.avatarUrl,
        });
    }
);
app.post('/token',
    passport.authenticate('local', {session: false}),
    function (req, res) {
        const user: User = req.user as any;
        return res.json(generateToken(user));
    }
);
app.post('/signup',
    function (req, res) {
        if (
            !req.body.name
            || typeof req.body.name !== 'string'
            || !req.body.password
            || typeof req.body.password !== 'string'
            || !req.body.email
            || typeof req.body.email !== 'string'
            || (req.body.avatarUrl && typeof req.body.avatarUrl !== 'string')
        ) {
            return res.sendStatus(400);
        }
        return UserModel.findOne({email: req.body.email}).exec(
        )
            .then(existingUser => {
                if (existingUser)
                    return res.status(409).json({
                        error: 'Email is already used'
                    });
                const user = new UserModel();
                user.name = req.body.name;
                user.password = req.body.password;
                user.email = req.body.email;
                user.avatarUrl = req.body.avatarUrl;
                user.save().then(
                    () => res.json(generateToken(user)));
            })
            .catch((err) => {
                logger.error(err);
                return res.sendStatus(500);
            })
    }
);
app.post('/logout',
    passport.authenticate('jwt', {session: false}),
    function (req, res) {
        const token: string = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
        const invalidToken = new BlacklistEntryModel();
        invalidToken.token = token;
        return invalidToken.save()
            .then(() => res.sendStatus(200));
    }
);
app.post('/forgot',
    function (req, res) {
        if (
            !req.body.email
            || typeof req.body.email !== 'string'
        ) {
            return res.sendStatus(400);
        }
        return UserModel.findOne({email: req.body.email}).exec()
            .then(user => {
                if (user) {
                    const resetToken: string = crypto.randomBytes(20).toString('hex');
                    user.resetToken = resetToken;
                    user.resetPasswordExpires = Date.now() + 3600000;
                    return user.save()
                        .then(() => {
                            return smtpTransport.sendMail({
                                to: user.email,
                                from: process.env.SMTP_FROM,
                                subject: 'Passwort zurücksetzen',
                                text: 'Du erhälst diese E-Mail da Du (oder jemand anderes) dein Passwort auf digital-stage.org zurücksetzen möchte.\n\n' +
                                    'Bitte klicke auf den folgenden Link, um Dein Passwort zurückzusetzen:\n\n' +
                                    process.env.RESET_URL + '?token=' + resetToken + '\n\n' +
                                    'Falls Du nicht Dein Passwort zurücksetzen wolltest, ignoriere bitte diese E-Mail.\n'
                            })
                                .then(() => logger.info("Send reset mail to " + user.email))
                                .then(() => res.sendStatus(200));
                        })
                        .catch(error => {
                            logger.error(error);
                            return res.sendStatus(500);
                        })
                }
                return res.sendStatus(404);
            });
    }
);
app.post('/reset',
    function (req, res) {
        if (
            !req.body.password
            || typeof req.body.password !== 'string'
            || !req.body.token
            || typeof req.body.token !== 'string'
        ) {
            return res.sendStatus(400);
        }
        return UserModel.findOne({
            resetToken: req.body.token,
            resetPasswordExpires: {$gt: Date.now()}
        })
            .then(user => {
                if (user) {
                    logger.info("User " + user.name + " reset password!");
                    user.password = req.body.password;
                    return user.save()
                        .then(() => res.sendStatus(200));
                }
                logger.debug("Invalid token used for reset");
                return res.sendStatus(401);
            })
            .catch(error => {
                logger.error(error);
                return res.sendStatus(500);
            });
    });

if (!process.env.USE_SSL || process.env.USE_SSL === "false") {
    app.listen(PORT);
    logger.info("SERVER LISTENING WITHOUT SSL ON PORT " + PORT);
} else {
    https.createServer({
        key: fs.readFileSync(
            path.resolve(process.env.SSL_KEY || './ssl/key.pem')
        ),
        cert: fs.readFileSync(
            path.resolve(process.env.SSL_CRT || './ssl/cert.pem')
        ),
        ca: process.env.SSL_CA ? fs.readFileSync(path.resolve(process.env.SSL_CA)) : undefined,
        requestCert: true,
        rejectUnauthorized: false
    });
    logger.info("SERVER LISTENING WITH SSL ON PORT " + PORT);
}