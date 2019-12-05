const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const randtoken = require('rand-token')
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt

const SECRET = 'ASDFUUSFASFSADFSFWEFMLIUIOPIOI'
const refreshTokens = {}
const opts = {}

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(passport.initialize())


opts.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('jwt');
opts.secretOrKey = SECRET;

passport.use(new JwtStrategy(opts,(jwtPayload, done) => {
    //If the token has expiration, raise unauthorized
    var expirationDate = new Date(jwtPayload.exp * 1000)
    if (expirationDate < new Date()) {
        return done(null, false);
    }
    var user = jwtPayload
    done(null, user)
}))

app.get('/', (req, res) => {
    res.send('ok')
})

app.post('/login', (req, res, next) => {
    const { username, password } = req.body
    const user = {
        username,
        role: 'admin'
    }
    const token = jwt.sign(user, SECRET, { expiresIn: 300 })
    const refreshToken = randtoken.uid(256)
    refreshTokens[refreshToken] = username
    res.json({
        token: 'JWT ' + token,
        refreshToken: refreshToken
    })
})

app.post('/token', function (req, res, next) {
    const { username, refreshToken } = req.body
    if ((refreshToken in refreshTokens) && (refreshTokens[refreshToken] == username)) {
        const user = {
            'username': username,
            'role': 'admin'
        }
        const token = jwt.sign(user, SECRET, { expiresIn: 300 })
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

app.get('/test_jwt', passport.authenticate('jwt',{session:false}), (req, res) => {
    res.json({ success: 'You are authenticated with JWT!', user: req.user })
})

app.listen(3000)