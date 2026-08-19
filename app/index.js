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

// I5 (Task 7 review): `application/vc+ld+json` (and the more generic
// `application/ld+json`) must be registered restify formatters, not just
// Content-Types we happen to set by hand with res.setHeader()/res.end() in
// app/routes/badge-instances.js's credential routes. restify's global
// `restify.plugins.acceptParser(server.acceptable)` (below) rejects any
// request whose `Accept` header doesn't match a KNOWN type with a 406
// NotAcceptableError before routing even happens — a real, spec-correct
// client requesting `Accept: application/vc+ld+json` (the exact content type
// these credentials are served as) would be rejected outright. Registering
// formatters here adds both types to `server.acceptable` (see
// restify's `mergeFormatters()`) so the accept-parser middleware allows them
// through. The formatter body itself mirrors restify's built-in JSON
// formatter (node_modules/restify/lib/formatters/json.js) — our credential
// routes bypass it entirely for the 200 case (res.end() with the exact
// stored/signed string, for byte-stability), but it's still what runs for
// any `res.send()` path through these routes (503/404/500 error bodies) when
// the client asked for one of these types.
//
// F1 (final whole-plan review): the same 406-before-routing problem applies
// to `application/did+json` — the media type a DID resolver actually sends
// as its `Accept` header when it dereferences `did:web:...`, per the did:web
// method spec. Without registering it here, every spec-correct resolver gets
// a 406 before `/.well-known/did.json`'s handler ever runs. Same formatter
// body (`formatVcLdJson` is generic — it just JSON.stringifies whatever body
// it's given), registered under this additional type.
function formatVcLdJson(req, res, body) {
  var data = 'null'
  if (body !== undefined) {
    try {
      data = JSON.stringify(body)
    } catch (e) {
      throw new restifyErrors.InternalServerError('could not format response body')
    }
  }
  res.setHeader('Content-Length', Buffer.byteLength(data))
  return data
}

const server = restify.createServer({
  name: package.name,
  version: package.version,
  log: logger,
  formatters: {
    'application/vc+ld+json': formatVcLdJson,
    'application/ld+json': formatVcLdJson,
    'application/did+json': formatVcLdJson,
  },
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
    // F1: served with the did:web method's own media type, not whatever
    // `res.send()`'s content-negotiation would otherwise pick from the
    // request's Accept header — a DID document is application/did+json
    // regardless of what a particular caller asked for (mirrors the
    // credential routes in app/routes/badge-instances.js, which likewise
    // hand-set Content-Type rather than rely on negotiation).
    res.setHeader('Content-Type', 'application/did+json')
    res.end(JSON.stringify(doc))
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
