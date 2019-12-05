const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const randtoken = require('rand-token')
const passport = require('passport')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt

// const SECRET = 'ASDFUUSFASFSADFSFWEFMLIUIOPIOI'
const privateKEY = fs.readFileSync('./private.key', 'utf8');
const publicKEY = fs.readFileSync('./public.key', 'utf8');

const refreshTokens = {}
const opts = {}

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(passport.initialize())


opts.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('jwt');
opts.secretOrKey = privateKEY;

passport.use(new JwtStrategy(opts, (jwtPayload, done) => {
    //If the token has expiration, raise unauthorized
    var expirationDate = new Date(jwtPayload.exp * 1000)
    if (expirationDate < new Date()) {
        return done(null, false);
    }
    var user = jwtPayload
    done(null, user)
}))

// issuer — Software organization who issues the token.
// subject — Intended user of the token.
// audience — Basically identity of the intended recipient of the token..
// expiresIn — Expiration time after which the token will be invalid.
// algorithm — Encryption algorithm to be used to protect the token.
const signOptions = {
    issuer: 'Mysoft corp',
    subject: 'some@user.com',
    audience: 'http://mysoftcorp.in',
    expiresIn: 300,
    algorithm: "RS256"
};

app.get('/', (req, res) => {
    res.send('ok')
})

app.post('/login', (req, res, next) => {
    const { username, password } = req.body

    const payload = {
        username,
        role: 'admin'
    }

    const token = jwt.sign(payload, privateKEY, signOptions)
    const refreshToken = randtoken.uid(256)
    refreshTokens[refreshToken] = username

    res.json({
        token: 'JWT ' + token,
        refreshToken: refreshToken
    })
})

app.post('/token', function (req, res, next) {

    // if (!req.header('Authorization')) {
    //     return res.send(401)
    // }
    // const authenHeader = req.header('Authorization')
    // const prefixAuthen = authenHeader.split(" ")
    // const token = prefixAuthen[1]
    // const legit = jwt.verify(token, publicKEY, signOptions);
    // console.log(legit)
    // console.log("\nJWT verification result: " + JSON.stringify(legit));

    const { username, refreshToken } = req.body
    if ((refreshToken in refreshTokens) && (refreshTokens[refreshToken] == username) && authenHeader) {
        const payload = {
            'username': username,
            'role': 'admin'
        }
        const token = jwt.sign(payload, privateKEY, signOptions)
        res.json({ token: 'JWT ' + token })
    }
    else {
        res.send(401)
    }
})

app.post('/token/reject', function (req, res, next) {
    const refreshToken = req.body.refreshToken
    if (refreshToken in refreshTokens) {
        delete refreshTokens[refreshToken]
    }
    res.send(204)
})

app.get('/test_jwt', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ success: 'You are authenticated with JWT!', user: req.user })
})

app.listen(3000)