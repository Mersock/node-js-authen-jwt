const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const randtoken = require('rand-token')

// const SECRET = 'ASDFUUSFASFSADFSFWEFMLIUIOPIOI'
const privateKEY = fs.readFileSync('./private.key', 'utf8');
const publicKEY = fs.readFileSync('./public.key', 'utf8');

const refreshTokens = {}

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

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

app.post('/token', function (req, res) {
    const { username, refreshToken } = req.body
    if ((refreshToken in refreshTokens) && (refreshTokens[refreshToken] == username)) {
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

app.get('/test_jwt', (req, res) => {
    try {
        const authenHeader = req.header('Authorization')
        const prefixAuthen = authenHeader.split(" ")
        const token = prefixAuthen[1]
        const legit = jwt.verify(token, publicKEY, signOptions);
        // console.log("\nJWT verification result: " + JSON.stringify(legit));
        res.send(legit)
    } catch (error) {
        console.log(error)
        res.send(401)
    }
})

app.listen(3000)