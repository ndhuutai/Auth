const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const User = require('./user');

const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;


const server = express();
// to enable parsing of json bodies for post requests
server.use(bodyParser.json());
server.use(session({
  secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re'
}));

/* Sends the given err, a string or an object, to the client. Sets the status
 * code appropriately. */
const sendUserError = (err, res) => {
  res.status(STATUS_USER_ERROR);
  if (err && err.message) {
    res.json({ message: err.message, stack: err.stack });
  } else {
    res.json({ error: err });
  }
};

const validateUser = (req, res, next) => {
  const cookie = req.session;
  if (!cookie.user) {
    sendUserError('must login', res);
    return;
  }
  User.findOne({ username: cookie.user.username }).exec()
    .then((user) => {
      req.user = user;
      next();
    })
    .catch(err => sendUserError(err, res));
};

// TODO: implement routes
server.post('/users', (req, res) => {
  const { username, password } = req.body;
  if (username && password) {
    bcrypt.hash(password, BCRYPT_COST).then((passwordHash) => {
      const newUser = new User({ username, passwordHash });
      newUser.save()
        .then(user => res.json(user))
        .catch(err1 => sendUserError('user already exists', res));
    });
  } else {
    sendUserError('Must provide username and password', res);
  }
});

server.post('/log-in', (req, res) => {
  const { username, password } = req.body;
  if (username && password) {
    User.findOne({ username }).exec()
      .then((user) => {
        bcrypt.compare(password, user.passwordHash, (err, isValid) => {
          if (err) {
            sendUserError(err, res);
          }
          if (isValid) {
            req.session.user = { username, authenticated: true };
            res.json({ success: true });
          } else {
            sendUserError('wrong password', res);
          }
        });
      })
      .catch(err => sendUserError(err, res));
  } else {
    sendUserError('must provide username and password', res);
  }
});

// TODO: add local middleware to this route to ensure the user is logged in
server.get('/me', validateUser, (req, res) => {
  // Do NOT modify this route handler in any way.
  res.json(req.user);
});

module.exports = { server };
