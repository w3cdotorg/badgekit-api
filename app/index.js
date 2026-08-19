var habitat = require("habitat");
habitat.load();

if (process.env.NODE_ENV === 'production') {
  const weak = ['devsecret', 'dev-cookie-secret', 'dev-api-secret', 'blah', undefined, ''];
  ['MASTER_SECRET'].forEach(function (name) {
    if (weak.indexOf(process.env[name]) !== -1)
      throw new Error(name + ' must be set to a strong value in production');
  });
}

const restify = require('restify');
const applyRoutes = require('./routes');
const logger = require('./lib/logger')
const middleware = require('./lib/middleware')
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

applyRoutes(server);

module.exports = server;

if (!module.parent) {
  server.listen(process.env.PORT || 8080, function () {
    console.log('%s listening at %s', server.name, server.url);
  });
}
