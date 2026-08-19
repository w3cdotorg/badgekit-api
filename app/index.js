var habitat = require("habitat");
habitat.load();

if (process.env.NODE_ENV === 'production') {
  const weak = ['devsecret', 'dev-cookie-secret', 'dev-api-secret', 'blah', undefined, ''];
  const MIN_SECRET_LENGTH = 32;
  ['MASTER_SECRET'].forEach(function (name) {
    const value = process.env[name];
    if (weak.indexOf(value) !== -1)
      throw new Error(name + ' must be set to a strong value in production');
    if (value.length < MIN_SECRET_LENGTH)
      throw new Error(name + ' must be at least ' + MIN_SECRET_LENGTH + ' characters long in production');
  });
}

const restify = require('restify');
const restifyErrors = require('restify-errors');
const applyRoutes = require('./routes');
const logger = require('./lib/logger')
const middleware = require('./lib/middleware')
const issuerKey = require('./lib/issuer-key')
const package = require('../package')

const server = restify.createServer({
  name: package.name,
  version: package.version,
  log: logger,
});

server.pre(restify.plugins.pre.sanitizePath());
server.use(restify.plugins.acceptParser(server.acceptable));
server.use(restify.plugins.queryParser({mapParams: false}));
server.use(restify.plugins.bodyParser({mapParams: false, rejectUnknown: true}));
server.use(middleware.verifyRequest())
server.use(middleware.attachResolvePath())
server.use(middleware.attachErrorLogger())
server.use(middleware.attachPageData())

server.get('/.well-known/did.json', function (req, res, next) {
  if (!issuerKey.isConfigured()) {
    res.send(503, {code: 'SigningNotConfigured', message: 'ISSUER_SIGNING_KEY / ISSUER_DID not set'})
    return next()
  }
  issuerKey.getDidDocument().then(function (doc) {
    res.send(200, doc)
    return next()
  }).catch(function (err) {
    // req.error(message) (the codebase convention, see e.g.
    // app/routes/claim-codes.js) logs at error level via
    // req.log.error(error, message) and then forwards the *original* error
    // to next() unchanged. For most routes that's fine because they sit
    // behind auth — but restify's default error handler renders any
    // non-restify Error as {code:'Internal', message: String(err)}, which
    // would leak internal details (e.g. a key-decoding TypeError's message)
    // straight into the response body. This route is intentionally
    // auth-exempt, so an unauthenticated caller could see that. Log the raw
    // error the same way req.error() would, but respond with a generic,
    // wrapped restify error instead of the raw one.
    req.log.error(err, 'Error building DID document')
    return next(new restifyErrors.InternalServerError('Error building DID document'))
  })
})

applyRoutes(server);

module.exports = server;

if (!module.parent) {
  server.listen(process.env.PORT || 8080, function () {
    console.log('%s listening at %s', server.name, server.url);
  });
}
