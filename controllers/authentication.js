const jwt = require('jsonwebtoken');
const User = require('../models/user');
const config = require('../config');

function getToken(user, expireIn, secret) {
  const timestamp = Math.floor(Date.now() / 1000); 
  return jwt.sign({ 
    sub: user.id,
    iat: timestamp ,
    exp: timestamp + expireIn, // + n min
  }, secret);
}

function getAccessToken(user) {
  return getToken(user, 60, config.accessTokenSecret);
}

function getRefreshToken(user) {
  return getToken(user, 600, config.refreshTokenSecret);
}

exports.token = function(req, res) {
  // extract bearer
  const refreshToken = req.get('authorization').substring(7);
  jwt.verify(refreshToken, config.refreshTokenSecret, function(err, decoded){
    if (err) {return res.status(422).send(err);}
    const accessToken = getAccessToken({id:decoded.sub});
    return res.send({accessToken});
  });
};

exports.signin = function(req, res) {
  // give user token
  const accessToken = getAccessToken(req.user);
  const refreshToken = getRefreshToken(req.user);
  return res.send({
    accessToken,
    refreshToken
  });
};

exports.signup = function (req, res, next) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(422).send({ error: 'Email and Password must not be empty' });
  }

  User.findOne({ email }, (err, existingUser) => {
    if (err) { return next(err); }
    // user Exist
    if (existingUser) {
      return res.status(422).send({ error: 'Email is used' });
    }
    const user = new User({
      email,
      password,
    });
    user.save((err) => {
      if (err) { return next(err) ;}
      // user created
      res.json({ token: getAccessToken(user) });
    });
  });
};
