const { signin, signup, token} = require('./controllers/authentication');
const passportService =require('./services/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', {session:false});
const requireSignin = passport.authenticate('local', {session:false});
module.exports = function(app) {

  app.get('/', requireAuth,function(req, res) {
    res.send({sucess: true});
  });

  app.post('/signin', requireSignin,  signin);
  app.post('/signup', signup);
  app.post('/token', token);
};