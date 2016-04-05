const passport = require('passport');
const User = require('../models/user');
const config = require('../config');

const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const LocalStrategy = require('passport-local')

// Create local strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function(email, password, done){
  // verify email and password
  // call done with the user if it's correct
  // otherwise call done with false
  User.findOne({ email: email }, function(err, user) {
    if (err) { return done(err); }
    if(!user) { return done(null, false); }

    // compare passwords
    user.comparePassword(password, function(err, isMatch) {
      if(err) { return done(err); }
      if(!isMatch) { return done(null, false); }
      else { return done(null, user); }
    });

  });
});

// Set options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// Create the Strategy

const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // see if the userid in the payload exists in the db
  // if it does, call done with that user
  // otherwise, call done without any user

  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false); }

    if(user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});

// Link strategy to passport
passport.use(jwtLogin);
passport.use(localLogin);
