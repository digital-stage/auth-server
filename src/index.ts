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
import {Strategy as JwtStrategy} from "passport-jwt";
import {ExtractJwt} from "passport-jwt";
import {User, UserModel, UserType} from "./store/UserModel";
import * as jwt from "jsonwebtoken";


const MONGOOSE_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:4321/auth";
export const PORT: number | string = process.env.PORT || 5000;
const logger = pino({
    level: process.env.LOG_LEVEL || 'info'
});
const SECRET = "secret";

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
    secretOrKey: SECRET
}, function (jwt_payload, done) {
    return UserModel.findById(jwt_payload.user._id).exec()
        .then(user => {
            if (user) {
                return done(null, user);
            }
            return done(null, false);
        })
        .catch(err => done(err, false));
}));

const generateToken = (user: User) => {
    return jwt.sign({
        user: {
            _id: user._id,
            email: user.email
        }
    }, SECRET);
}

app.get('/', function (req, res) {
    res.send('Hello World!');
});

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
        console.log("PROFILE");
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

if (process.env.NODE_ENV === "development") {
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