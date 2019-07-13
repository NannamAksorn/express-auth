const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local strategy
const localOptions = {usernameField: 'email'};
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  User.findOne({email:email}, function(err,user) {
    if (err) {return done(err);}
    if(!user) {return done(null, false);}

    // compare password
    user.comparePassword(password, function(err, isMatch) {
      if (err) { return done(err);}
      if(!isMatch) {return done(null, false);}

      return done(null, user);
    });

  });
});

// Setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.accessTokenSecret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
  // If user Id in db, call done with User
  // else, call done without user
  User.findById(payload.sub, function(err, user){
    if (err) {return done(err, false);}
    if(user){
      done(null, user);
    } else {
      done(null,false);
    }
  });
});

// User Strategy
passport.use(jwtLogin);
passport.use(localLogin);