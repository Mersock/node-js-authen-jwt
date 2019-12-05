const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const randtoken = require('rand-token')

const SECRET = 'ASDFUUSFASFSADFSFWEFMLIUIOPIOI'
const refreshTokens = {}

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended:true}))

app.get('/',(req,res) => {
    res.send('ok')
})

app.post('/login',(req,res,next) => {
    const {username,password} = req.body
    const user = {
        username,
        role:'admin'
    }
    const token = jwt.sign(user,SECRET,{expiresIn:300})
    const refreshToken = randtoken.uid(256)
    refreshTokens[refreshToken] = username
    console.log('refreshToken',refreshTokens)
    res.json({
        token:'JWT'+token,
        refreshToken:refreshToken
    })
})

app.post('/token', function (req, res, next) {
    const {username,refreshToken} = req.body
    if((refreshToken in refreshTokens) && (refreshTokens[refreshToken] == username)) {
      const user = {
        'username': username,
        'role': 'admin'
      }
      const token = jwt.sign(user, SECRET, { expiresIn: 300 })
      res.json({token: 'JWT ' + token})
    }
    else {
      res.send(401)
    }
  })

  app.post('/token/reject', function (req, res, next) { 
    const refreshToken = req.body.refreshToken 
    if(refreshToken in refreshTokens) { 
      delete refreshTokens[refreshToken]
    } 
    res.send(204) 
  })

app.listen(3000)