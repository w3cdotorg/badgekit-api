const Promise = require('bluebird')
const util = require('util')
const unixtimeFromDate = require('../lib/unixtime-from-date')
const sha256 = require('../lib/hash').sha256
const customError = require('../lib/custom-error')
const sendPaginated = require('../lib/send-paginated')
const Badges = require('../models/badge')
const ClaimCodes = require('../models/claim-codes')
const Webhooks = require('../models/webhook')
const BadgeInstances = require('../models/badge-instance')
const Milestones = require('../models/milestone')
const errorHelper = require('../lib/error-helper')
const middleware = require('../lib/middleware')
const log = require('../lib/logger')
const restifyErrors = require('restify-errors')
const issuerKey = require('../lib/issuer-key')
const ob3 = require('../lib/ob3')
const ob3Signer = require('../lib/ob3-signer')
const makeBadgeClassUrl = require('./utils').makeBadgeClassUrl
const extend = require('xtend')
const async = require('async')

const findSystemBadge = [
  middleware.findSystem(),
  middleware.findBadge({
    relationships: true,
    where: {systemId: ['system', 'id']},
  }),
]
const findIssuerBadge = [
  middleware.findSystem(),
  middleware.findIssuer({where: {systemId: ['system', 'id']}}),
  middleware.findBadge({
    relationships: true,
    where: {
      systemId: ['system', 'id'],
      issuerId: ['issuer', 'id'],
    },
  }),
]
const findProgramBadge = [
  middleware.findSystem(),
  middleware.findIssuer({where: {systemId: ['system', 'id']}}),
  middleware.findProgram({where: {issuerId: ['issuer', 'id']}}),
  middleware.findBadge({
    relationships: true,
    where: {
      systemId: ['system', 'id'],
      issuerId: ['issuer', 'id'],
      programId: ['program', 'id'],
    },
  }),
]

const findSystemBadgeInstance = [
  middleware.findSystem(),
  middleware.findBadge({where: {systemId: ['system', 'id']}}),
  middleware.findBadgeInstance({
    field: 'email',
    param: 'instanceEmail',
    where: {badgeId: ['badge', 'id']},
    relationships: true,
    relationshipsDepth: 2
  }),
]

const findIssuerBadgeInstance = [
  middleware.findSystem(),
  middleware.findIssuer({where: {systemId: ['system', 'id']}}),
  middleware.findBadge({where: {issuerId: ['issuer', 'id']}}),
  middleware.findBadgeInstance({
    field: 'email',
    param: 'instanceEmail',
    where: {badgeId: ['badge', 'id']},
    relationships: true,
    relationshipsDepth: 2
  }),
]

const findProgramBadgeInstance = [
  middleware.findSystem(),
  middleware.findIssuer({where: {systemId: ['system', 'id']}}),
  middleware.findProgram({where: {issuerId: ['issuer', 'id']}}),
  middleware.findBadge({where: {programId: ['program', 'id']}}),
  middleware.findBadgeInstance({
    field: 'email',
    param: 'instanceEmail',
    where: {badgeId: ['badge', 'id']},
    relationships: true,
    relationshipsDepth: 2
  }),
]

const prefix = {
  system: '/systems/:systemSlug',
  issuer: '/systems/:systemSlug/issuers/:issuerSlug',
  program: '/systems/:systemSlug/issuers/:issuerSlug/programs/:programSlug',
}
const publicPrefix = {
  // `prefix.*` already starts with `/`, so don't add a second one here -
  // the resulting double slash (`/public//systems/...`) never matches a
  // sanitized incoming request path.
  system: '/public' + prefix.system,
  issuer: '/public' + prefix.issuer,
  program: '/public' + prefix.program,
}

function instanceToHookData(badge, instance, comment) {
  return {
    action: 'award',
    uid: instance.slug,
    badge: badge.toResponse(),
    email: instance.email,
    assertionUrl: instance.assertionUrl,
    // OB 3.0 (Task 7): additive, next to assertionUrl.
    credentialUrl: instance.credentialUrl,
    issuedOn: unixtimeFromDate(instance.issuedOn),
    comment: comment
  }
}

exports = module.exports = function applyBadgeRoutes (server) {
  const createNewInstanceSuffix = '/badges/:badgeSlug/instances'
  server.post(prefix.system + createNewInstanceSuffix,
              findSystemBadge, createNewInstance)

  server.post(prefix.issuer + createNewInstanceSuffix,
              findIssuerBadge, createNewInstance)

  server.post(prefix.program + createNewInstanceSuffix,
              findProgramBadge, createNewInstance)

  function createNewInstance(req, res, next) {
    const badge = req.badge;
    const system = req.system
    const row = BadgeInstances.formatUserInput(req.body)
    row.badgeId = badge.id

    const errs = BadgeInstances.validateRow(row)
    if (errs.length)
      return res.send(400, errorHelper.validation(errs));

    if (!row.claimCode)
      return saveBadgeInstance()

    function errorHandler(err) {
      log.error(err, 'error interacting with database in route for creating a new badge instance')
      return next(err)
    }

    const query = {
      code: row.claimCode,
      badgeId: row.badgeId
    }

    ClaimCodes.getOne(query)
      .then(function (code) {
        if (code.claimed && !code.multiuse) {
          const response = {
            code: 'CodeAlreadyUsed',
            message: 'Claim code `'+code.code+'` has already been claimed'
          }
          res.send(400, response)
          return Promise.reject(response)
        }
        code.claimed = true
        code.email = row.email
        return ClaimCodes.put(code)
      })
      .then(saveBadgeInstance)
      .catch(function (err) {
        if (err.code !== 'CodeAlreadyUsed')
          return errorHandler(err)
      })

    function saveBadgeInstance(err) {
      const MissingWebhookError = customError('MissingWebhookError');

      var hookData = [];
      var instance;
      BadgeInstances.put(row)
        .then(function (result) {
          instance = BadgeInstances.toResponse(result.row, req);

          res.header('Location', '/public/assertions/' + row.slug)
          res.send(201, {
            status: 'created',
            instance: instance,
          })

          // Webhook stuff shouldn't hold up the request, so we call
          // `next()` before looking up any hooks we have to send off
          next()

          const comment = req.body.comment || null;
          hookData.push(instanceToHookData(badge, instance, comment))

          return Milestones.findAndAward(instance.email, badge);
        })

        .then(function (instances) {
          instances.forEach(function (instance) {
            instance = BadgeInstances.toResponse(instance, req);
            hookData.push(instanceToHookData(badge, instance))
          })
          return Webhooks.getOne({systemId: system.id});
        })

        .then(function (hook) {
          if (!hook)
            throw new MissingWebhookError();

          return Promise.all(hookData.map(hook.call.bind(hook)))
        })

        .then(function (results) {
          results.forEach(function (result) {
            const res = result.res;
            const body = result.body;
            if (res.statusCode != 200) {
              return log.warn({
                code: 'WebhookBadResponse',
                status: res.statusCode,
                body: body
              })
            }
          })
        })
        .catch(MissingWebhookError, function () {
          return log.info({
            code: 'WebhookNotFound',
            system: system
          }, 'Webhook not found for system')
        })
        .catch(function (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            const query = {
              email: row.email,
              badgeId: req.badge.id
            }
            BadgeInstances.getOne(query)
              .then(function (instance) {
                const otherAssertionUrl = req.resolvePath('/public/assertions/' + instance.slug);
                const message = 'User ' + row.email + ' has already been awarded badge ' + req.badge.slug
                return res.send(409, {
                  code: 'ResourceConflict',
                  message: message,
                  details: {
                    assertionUrl: otherAssertionUrl
                  }
                });
              })

              .catch(function (err) {
                log.error(err, 'error fetching pre-existing badge instance');
                return next(err);
              })
          }
          else {
            log.error(err, 'error dealing with webhooks when awarding badge')
            return next(err);
          }
        })
    }
  }

  const createNewInstancesSuffix = '/badges/:badgeSlug/instances/bulk'
  server.post(prefix.system + createNewInstancesSuffix,
              findSystemBadge, createNewInstances)

  server.post(prefix.issuer + createNewInstancesSuffix,
              findIssuerBadge, createNewInstances)

  server.post(prefix.program + createNewInstancesSuffix,
              findProgramBadge, createNewInstances)

  function createNewInstances(req, res, next) {
    const badge = req.badge;
    const system = req.system;

    var emails = req.body.emails;
    if (!(emails instanceof Array))
      return res.send(400, new Error('Invalid value for "emails".  Expected array.'));

    var rows = [];
    emails.forEach(function (email) {
      var row = BadgeInstances.formatUserInput(extend(req.body, {email: email} ));
      row.badgeId = badge.id;
      if (row.claimCode)
        delete row.claimCode;

      rows.push(row);
    });

    var errs = [];
    rows.forEach(function (row) {
      errs = errs.concat(BadgeInstances.validateRow(row));
    });

    if (errs.length)
      return res.send(400, errorHelper.validation(errs));

    var instances = [];
          
    return Webhooks.getOne({systemId: system.id}, function(err, hook) {
      if (!hook) {
        log.info({
            code: 'WebhookNotFound',
            system: system
          }, 'Webhook not found for system');
      }

      async.each(rows, saveBadgeInstance, function (err) {
        if (err)
          return next(err);

        return res.send(201, { status: 'created', instances: instances  });
      });

      function saveBadgeInstance(row, callback) {
        const MissingWebhookError = customError('MissingWebhookError');
        var hookData = [];
        var instance;
        BadgeInstances.put(row, function(err, result) {
          if (err) {
            if (err.code === 'ER_DUP_ENTRY')
              return callback();
            else {
              return callback(err);
            }
          }

          instance = BadgeInstances.toResponse(result.row, req);

          instances.push(instance);

          callback();

          const comment = req.body.comment || null;
          hookData.push(instanceToHookData(badge, instance, comment))

          Milestones.findAndAward(instance.email, badge)
            .then(function (instances) {
              instances.forEach(function (instance) {
                instance = BadgeInstances.toResponse(instance, req);
                hookData.push(instanceToHookData(badge, instance))
              })

              if (!hook)
                throw new MissingWebhookError();
              return Promise.all(hookData.map(hook.call.bind(hook)))
            })

            .then(function (results) {
              results.forEach(function (result) {
                const res = result.res;
                const body = result.body;
                if (res.statusCode != 200) {
                  return log.warn({
                    code: 'WebhookBadResponse',
                    status: res.statusCode,
                    body: body
                  })
                }
              })
            })
            .catch(MissingWebhookError, function () {
              return;
            })
            .catch(function (err) {
              if (err.code !== 'ER_DUP_ENTRY') {
                log.error(err, 'error dealing with webhooks when awarding badge')
                return;
              }
            })
        });
      }
    })
  }

  const getInstancesSuffix = '/badges/:badgeSlug/instances'
  server.get(prefix.system + getInstancesSuffix,
             findSystemBadge, getBadgeInstances)
  server.get(prefix.issuer + getInstancesSuffix,
             findIssuerBadge, getBadgeInstances)
  server.get(prefix.program + getInstancesSuffix,
             findProgramBadge, getBadgeInstances)
  function getBadgeInstances(req, res, next) {
    var options = {relationships: true, relationshipsDepth: 2};

    if (req.pageData) {
      options.limit = req.pageData.count;
      options.page = req.pageData.page;
      options.includeTotal = true;
    }

    BadgeInstances.get({ badgeId: req.badge.id}, options).then(function (result) {
      var total = 0;
      var rows = result;
      if (req.pageData) {
        total = result.total;
        rows = result.rows;
      }
      var responseData = {instances: rows.map(function (row) { return BadgeInstances.toResponse(row, req); })}
      return sendPaginated(req, res, responseData, total);
    })
    .catch(function (err) {
      log.error(err, 'error fetching badge instances');
      return next(err);
    });
  }

  const getInstanceSuffix = '/badges/:badgeSlug/instances/:instanceEmail'
  server.get(prefix.system + getInstanceSuffix,
             findSystemBadgeInstance, getBadgeInstance)
  server.get(prefix.issuer + getInstanceSuffix,
             findIssuerBadgeInstance, getBadgeInstance)
  server.get(prefix.program + getInstanceSuffix,
             findProgramBadgeInstance, getBadgeInstance)
  function getBadgeInstance(req, res, next) {
    return res.send({instance: BadgeInstances.toResponse(req.badgeInstance, req)});
  }


  const deleteInstanceSuffix = '/badges/:badgeSlug/instances/:instanceEmail'
  server.del(prefix.system + deleteInstanceSuffix,
             findSystemBadgeInstance, deleteBadgeInstance)
  server.del(prefix.issuer + deleteInstanceSuffix,
             findIssuerBadgeInstance, deleteBadgeInstance)
  server.del(prefix.program + deleteInstanceSuffix,
             findProgramBadgeInstance, deleteBadgeInstance)
  function deleteBadgeInstance(req, res, next) {
    BadgeInstances.del({id: req.badgeInstance.id}).then(function () {
      res.send({instance: BadgeInstances.toResponse(req.badgeInstance, req)});

      // Webhook stuff shouldn't hold up the request, so we call
      // `next()` before looking up any hooks we have to send off
      next()

      hookData = {
        action: 'revoke',
        uid: req.badgeInstance.slug,
        badge: req.badge.toResponse(),
        email: req.badgeInstance.email
      }
      return Webhooks.getOne({systemId: req.system.id})
    }).then(function (hook) {
      if (!hook)
        return log.info({code: 'WebhookNotFound', system: req.system}, 'Webhook not found for system')

      hook.call(hookData, function (err, res, body) {
        if (err)
          return log.warn({code: 'WebhookRequestError', error: err})
        if (res.statusCode != 200)
          return log.warn({code: 'WebhookBadResponse', status: res.statusCode, body: body})
      })
    })
    .catch(function (err) {
      log.error(err, 'error deleting badge instance');
      return next(err);
    });
  }

  const getUserInstancesSuffix = '/instances/:email'
  server.get(prefix.system + getUserInstancesSuffix, [
    middleware.findSystem(),
    getUserInstances
  ]);
  server.get(prefix.issuer + getUserInstancesSuffix, [
    middleware.findSystem(),
    middleware.findIssuer({where: {systemId: ['system', 'id']}}),
    getUserInstances
  ]);
  server.get(prefix.program + getUserInstancesSuffix, [
    middleware.findSystem(),
    middleware.findIssuer({where: {systemId: ['system', 'id']}}),
    middleware.findProgram({where: {issuerId: ['issuer', 'id']}}),
    getUserInstances
  ]);
  function getUserInstances(req, res, next) {
    const email = req.params.email;
    const systemId = req.system ? req.system.id : null;
    const issuerId = req.issuer ? req.issuer.id : null;
    const programId = req.program ? req.program.id : null;

    const query = 'SELECT i.`id` FROM $table i'
               +  ' INNER JOIN `badges` b ON b.`id`=i.`badgeId`'
               +  ' WHERE i.`email` = ?'
               +  ' AND b.`systemId` = ?';

    const queryParams = [email, systemId];

    if (req.issuer) {
      query += ' AND b.`issuerId` = ?';
      queryParams.push(issuerId);
    }

    if (req.program) {
      query += ' AND b.`programId` = ?';
      queryParams.push(programId);
    }

    BadgeInstances.get([query, queryParams]).then(function (rows) {
      var instanceIds = rows.map(function(row) { return row.id; });
      if (instanceIds.length) {
        var options = { relationships: true, relationshipsDepth: 2 };
        if (req.pageData) {
          options.limit = req.pageData.count;
          options.page = req.pageData.page;
          options.includeTotal = true;
        }

        return BadgeInstances.get( { id: instanceIds }, options);
      }
      else {
        return Promise.resolve([]);
      }
    }).then(function (result) {
      var total = 0;
      var rows = result;
      if (req.pageData) {
        total = result.total;
        rows = result.rows;
      }

      var responseData = {instances: rows.map(function (row) { return BadgeInstances.toResponse(row, req); })}
      return sendPaginated(req, res, responseData, total);
    }).catch(function (err) {
      if (!err.restCode)
        log.error(err, 'unknown error in getUserInstances route')
      return next(err)
    });
  }

  server.get('/public/assertions/:instanceSlug', getAssertion)
  function getAssertion(req, res, next) {
    const data = {}
    const instanceSlug = req.params.instanceSlug
    const query = {slug: instanceSlug}
    const options = {relationships: true}
    BadgeInstances.getOne(query, options).then(function (instance) {
      if (!instance)
        return Promise.reject(errorHelper.notFound('Could not find badge instance'))

      data.instance = instance
      // get fully hydrated badge class
      const query = {id: instance.badge.id}
      const options = {relationships: true}
      return Badges.getOne(query, options)
    }).then(function (badge) {
      const instance = data.instance
      instance.badge = badge
      const assertion = makeAssertion(instance, req)
      res.send(200, assertion)
      return next()
    }).catch(function (err) {
      if (!err.restCode)
        log.error(err, 'unknown error in assertion route')
      return next(err)
    })
  }
  function makeAssertion(instance, req) {
    const badge = instance.badge
    return {
      uid: instance.slug,
      recipient: {
        identity: 'sha256$' + sha256(instance.email),
        type: 'email',
        hashed: true,
      },
      badge: req.resolvePath(makeBadgeClassUrl(badge)),
      verify: {
        url: req.resolvePath('/public/assertions/' + instance.slug),
        type: 'hosted',
      },
      issuedOn: unixtimeFromDate(instance.issuedOn),
      expires: unixtimeFromDate(instance.expires),
    }
  }

  // OB 3.0 (Task 7): baseUrl for signed credentials — env `PUBLIC_BASE_URL`
  // ONLY. This is deliberate and load-bearing, not a convenience default:
  //
  //   CRITICAL FIX (post-review): these two routes are auth-EXEMPT (see
  //   app/lib/middleware.js#verifyRequest(), `/public/` prefix) and were
  //   previously falling back to `req.resolvePath('/')`, which derives from
  //   the client-controlled `Host`/`X-Forwarded-Host` header. The very FIRST
  //   anonymous GET would pick whatever host it sent, and that host would be
  //   signed into `credential.id` / `achievement.id` / `credentialStatus.*`
  //   and PERSISTED FOREVER (lazy-sign-once). Any later GET — including from
  //   the real intended host — would keep being served that first,
  //   attacker-chosen, cryptographically-signed URL. There is no safe
  //   request-derived fallback here: every URL baked into a signed document
  //   must come from one operator-controlled, non-client-influenced value.
  //
  // Consequently: `PUBLIC_BASE_URL` is now MANDATORY whenever signing is
  // configured (`issuerKey.isConfigured()`). If it's unset, these routes
  // return the same 503 `SigningNotConfigured` shape used for a missing
  // key/DID (still just "signing isn't fully configured yet"), naming
  // `PUBLIC_BASE_URL` explicitly, rather than falling back to anything
  // Host-derived. The dev/staging stack (badgekit-stack) is expected to set
  // `PUBLIC_BASE_URL` alongside `ISSUER_SIGNING_KEY`/`ISSUER_DID`; there is no
  // `.env.sample`/`.env.example` in this repo to also update (checked).
  function getConfiguredBaseUrl() {
    const configured = process.env.PUBLIC_BASE_URL
    if (!configured) return null
    return configured.replace(/\/+$/, '')
  }

  // ONE baseUrl value feeds every URL built for a signed credential — the
  // credential id itself (ob3.buildCredential), the achievement/BadgeClass
  // URL, and the achievement image URL. None of these may derive from
  // `req` (see getConfiguredBaseUrl()'s comment above).
  function resolveImageUrl(badge, baseUrl) {
    if (!badge.image) return undefined
    var imageUrl = badge.image.toUrl()
    if (!/^http/.test(imageUrl))
      imageUrl = baseUrl + imageUrl
    return imageUrl
  }

  // Assembles the `badge` shape app/lib/ob3.js#buildCredential() expects.
  // Deliberately NOT `req.resolvePath(makeBadgeClassUrl(badge))` (that's
  // makeAssertion()'s job, for the 1.x, Host-derived-and-fine-because-
  // unsigned assertion) — every field here is baseUrl-derived so the signed
  // credential never bakes in a client-controlled host.
  function makeBadgeForCredential(badge, baseUrl) {
    return {
      name: badge.name,
      consumerDescription: badge.consumerDescription,
      url: baseUrl + makeBadgeClassUrl(badge),
      criteriaUrl: badge.criteriaUrl,
      criteria: badge.criteria || [],
      alignments: badge.alignments || [],
      imageUrl: resolveImageUrl(badge, baseUrl),
    }
  }

  const SIGNING_NOT_CONFIGURED = {
    code: 'SigningNotConfigured',
    message: 'ISSUER_SIGNING_KEY / ISSUER_DID not set',
  }
  const PUBLIC_BASE_URL_NOT_CONFIGURED = {
    code: 'SigningNotConfigured',
    message: 'PUBLIC_BASE_URL not set — required to sign credentials with a ' +
      'stable, operator-controlled base URL (never derived from the ' +
      'request Host header)',
  }
  const CREDENTIAL_CONTENT_TYPE = 'application/vc+ld+json'

  // F3 (final whole-plan review): builds the "ISSUER_DID and PUBLIC_BASE_URL
  // disagree" 503 body. Names both configured values so an operator staring
  // at this response (or a log line) can immediately see which one is wrong,
  // rather than having to go re-derive the mismatch themselves.
  function makeCoherenceMismatchError(baseUrl, baseUrlHost, didHost) {
    return {
      code: 'SigningNotConfigured',
      message: 'ISSUER_DID (' + issuerKey.getDid() + ', host `' + didHost + '`) does not ' +
        'agree with PUBLIC_BASE_URL (' + baseUrl + ', host `' + baseUrlHost + '`) — ' +
        'these must name the same host[:port], or credentials get signed whose ' +
        'issuer identity and content host silently, permanently diverge. Set ' +
        'ISSUER_DID and PUBLIC_BASE_URL together (see docs/ob3-operations.md ' +
        'in badgekit-stack for the domain-move runbook).',
    }
  }

  // Shared gate for both credential routes: sends the 503 itself (still
  // calling `next()`, matching every other route in this file) and returns
  // `null` when signing isn't fully configured; returns the baseUrl string
  // otherwise. Callers must check for `null` and stop.
  //
  // F3 (final whole-plan review): beyond "is a key/DID/base URL configured
  // at all", this now also enforces that they're COHERENT with each other —
  // the did:web host encoded in ISSUER_DID must equal the host[:port] of
  // PUBLIC_BASE_URL. Without this, a misconfiguration (e.g. ISSUER_DID left
  // pointing at an old domain after PUBLIC_BASE_URL was updated, or vice
  // versa) would silently sign credentials whose `issuer.id` host and
  // `id`/`achievement.id` host disagree — permanently, since credentials are
  // immutable once issued.
  function getSigningBaseUrlOrFail(res, next) {
    if (!issuerKey.isConfigured()) {
      res.send(503, SIGNING_NOT_CONFIGURED)
      next()
      return null
    }
    const baseUrl = getConfiguredBaseUrl()
    if (!baseUrl) {
      res.send(503, PUBLIC_BASE_URL_NOT_CONFIGURED)
      next()
      return null
    }
    const didHost = issuerKey.getDidHost()
    var baseUrlHost
    try {
      baseUrlHost = new URL(baseUrl).host
    } catch (e) {
      baseUrlHost = null
    }
    if (!didHost || !baseUrlHost || didHost !== baseUrlHost) {
      res.send(503, makeCoherenceMismatchError(baseUrl, baseUrlHost, didHost))
      next()
      return null
    }
    return baseUrl
  }

  // Mirrors the wrapping pattern in app/index.js's `/.well-known/did.json`
  // route (I6, post-review): these two routes are auth-EXEMPT, so an
  // unexpected internal error must never reach the client as a raw
  // `next(err)` — restify's default error renderer would serialize any
  // plain Error as `{code:'Internal', message: String(err)}`, potentially
  // leaking internal details (stack-adjacent messages, key-handling errors,
  // etc.) to an unauthenticated caller. restify errors we raise ourselves on
  // purpose (e.g. the 404 from errorHelper.notFound()) are passed through
  // unchanged; anything else is logged and replaced with a generic wrapped
  // error.
  function failSafely(req, next, context) {
    return function (err) {
      if (err && err.restCode)
        return next(err)
      req.log.error(err, context)
      return next(new restifyErrors.InternalServerError(context))
    }
  }

  // F3 (final whole-plan review): logs (never blocks/rewrites — byte-
  // stability wins) when a STORED credential's `id` doesn't start with the
  // currently-configured baseUrl. Parses the stored string only to peek at
  // `.id` for this check; the exact stored string is still what gets served.
  // Swallows a parse failure silently — an unparseable stored credential is
  // an existing-data problem this check isn't meant to surface twice over
  // (the byte-stable serve path below doesn't parse it at all).
  function warnIfCredentialIdIsStale(req, instance, baseUrl) {
    var parsed
    try {
      parsed = JSON.parse(instance.credential)
    } catch (e) {
      return
    }
    if (parsed && typeof parsed.id === 'string' && parsed.id.indexOf(baseUrl) !== 0) {
      req.log.warn(
        {instanceSlug: instance.slug, credentialId: parsed.id, currentBaseUrl: baseUrl},
        'Serving a stored OB3 credential whose id does not start with the ' +
        'current PUBLIC_BASE_URL — likely signed before a domain move; ' +
        'serving it verbatim (byte-stability), not re-signing it.'
      )
    }
  }

  // F2 (final whole-plan review): the status list is fixed-size (131,072
  // entries, global-constraints.md); sharded per app/lib/ob3.js so instance
  // ids beyond the ceiling get a NEW list rather than an out-of-range,
  // silently-wrong bit index signed into an immutable credential. `:shard`
  // must be a canonical non-negative integer (no leading zeros, no sign) —
  // anything else 404s rather than reaching the signing gate, since it can
  // never correspond to a real shard regardless of configuration.
  const SHARD_PARAM_PATTERN = /^(0|[1-9]\d*)$/
  server.get('/public/credentials/status/:shard', getStatusListCredential)
  function getStatusListCredential(req, res, next) {
    const shardParam = req.params.shard
    if (!SHARD_PARAM_PATTERN.test(shardParam))
      return next(errorHelper.notFound('Invalid status list shard: ' + shardParam))
    const shard = parseInt(shardParam, 10)

    const baseUrl = getSigningBaseUrlOrFail(res, next)
    if (!baseUrl) return

    ob3Signer.getStatusListCredential(baseUrl, shard).then(function (signed) {
      res.setHeader('Content-Type', CREDENTIAL_CONTENT_TYPE)
      res.end(JSON.stringify(signed))
      return next()
    }).catch(failSafely(req, next, 'Error building OB3 status list credential'))
  }

  // I3 (post-review): collapses concurrent first-GETs for the SAME instance
  // within this process into a single sign, keyed by slug. Without this, two
  // requests racing the `instance.credential === null` check would each
  // independently build+sign (different `proof.created` timestamps ->
  // different bytes) and `UPDATE` the row — a real byte-stability hazard.
  // This alone only protects against in-process races; see the CAS + re-read
  // below for the fully authoritative (cross-process-safe) guarantee.
  const signingInFlight = {}

  function signAndPersistCredential(instance, baseUrl) {
    const key = instance.slug
    if (signingInFlight[key]) return signingInFlight[key]

    const promise = Badges.getOne({id: instance.badgeId}, {relationships: true}).then(function (badge) {
      const issuerOrg = makeIssuerOrganization(badge.program, badge.issuer, badge.system)
      const badgeForCredential = makeBadgeForCredential(badge, baseUrl)
      const unsigned = ob3.buildCredential({
        instance: instance,
        badge: badgeForCredential,
        issuerOrg: issuerOrg,
        baseUrl: baseUrl,
        issuerDid: issuerKey.getDid(),
      })
      return ob3Signer.signCredential(unsigned)
    }).then(function (signed) {
      const serialized = JSON.stringify(signed)
      // Conditional/authoritative persistence (I3, post-review): the
      // `credential: null` condition makes this a compare-and-swap — it only
      // writes if the row is STILL unsigned, so if another request (in this
      // process despite the in-flight map above, or in a different process
      // entirely) already won the race, this `UPDATE` is a no-op rather than
      // clobbering an already-served value (last-write-wins would otherwise
      // let two already-served responses diverge from what ends up stored).
      // Either way, we then ALWAYS re-read the row and serve exactly what is
      // actually persisted now, not our own locally-computed `serialized` —
      // this is what makes every racing caller converge on identical bytes.
      return BadgeInstances.update({credential: serialized}, {id: instance.id, credential: null})
        .then(function () { return BadgeInstances.getOne({id: instance.id}) })
        .then(function (persisted) { return persisted.credential })
    }).finally(function () {
      delete signingInFlight[key]
    })

    signingInFlight[key] = promise
    return promise
  }

  server.get('/public/credentials/:instanceSlug', getCredential)
  function getCredential(req, res, next) {
    const baseUrl = getSigningBaseUrlOrFail(res, next)
    if (!baseUrl) return

    const instanceSlug = req.params.instanceSlug
    BadgeInstances.getOne({slug: instanceSlug}).then(function (instance) {
      if (!instance)
        return Promise.reject(errorHelper.notFound('Could not find badge instance'))

      // Byte-stable persistence: once signed, ALWAYS serve the exact stored
      // string back, verbatim — never re-serialize a parsed object (key
      // order/whitespace could differ from run to run of JSON.stringify on a
      // freshly-built object, even if logically equivalent).
      //
      // F3 (final whole-plan review): a stored credential's `id` was baked in
      // with WHATEVER `PUBLIC_BASE_URL` was configured at sign time. If the
      // operator later moves domains (new PUBLIC_BASE_URL/ISSUER_DID pair),
      // any credential signed under the old base URL still has the old host
      // in its `id` — and byte-stability means we deliberately keep serving
      // it verbatim rather than silently rewrite an already-issued,
      // (potentially externally-recorded) credential. Still worth a log line
      // so this doesn't go unnoticed operationally.
      if (instance.credential) {
        warnIfCredentialIdIsStale(req, instance, baseUrl)
        return instance.credential
      }

      // Lazy sign: instances created before signing existed (or before this
      // credential was ever requested) have `credential IS NULL`.
      return signAndPersistCredential(instance, baseUrl)
    }).then(function (serialized) {
      res.setHeader('Content-Type', CREDENTIAL_CONTENT_TYPE)
      res.end(serialized)
      return next()
    }).catch(failSafely(req, next, 'Error building/serving OB3 credential'))
  }

  server.get(publicPrefix.system +'/badges/:badgeSlug',
              findSystemBadge, getBadgeClass)

  server.get(publicPrefix.issuer +'/badges/:badgeSlug',
              findIssuerBadge, getBadgeClass)

  server.get(publicPrefix.program+'/badges/:badgeSlug',
              findProgramBadge, getBadgeClass)
  function getBadgeClass(req, res, next) {
    const badgeClass = makeBadgeClass(req.badge, req)
    res.send(200, badgeClass)
    return next()
  }
  function makeBadgeClass(badge, req) {
    // #TODO: alignment urls, tags
    var imageUrl = badge.image.toUrl()
    if (!/^http/.test(imageUrl))
      imageUrl = req.resolvePath(imageUrl)
    return {
      name: badge.name,
      description: badge.consumerDescription,
      image: imageUrl,
      criteria: badge.criteriaUrl,
      alignment: badge.alignments.map(function(alignment) { return { name: alignment.name, url: alignment.url, description: alignment.description } }),
      issuer: req.resolvePath(publicIssuerUrl(badge)),
    }
  }
  function publicIssuerUrl(badge) {
    const system = badge.system
    const issuer = badge.issuer
    const program = badge.program
    if (program && program.slug)
      return util.format('/public/systems/%s/issuers/%s/programs/%s',
                         system.slug, issuer.slug, program.slug)
    if (issuer && issuer.slug)
      return util.format('/public/systems/%s/issuers/%s',
                         system.slug, issuer.slug)
    if (badge.system && badge.system.slug)
      return util.format('/public/systems/%s', system.slug)
  }

  server.get('/public/systems/:systemSlug', [
    middleware.findSystem({relationships: true}),
    getIssuerClass,
  ])
  server.get('/public/systems/:systemSlug/issuers/:issuerSlug', [
    middleware.findSystem(),
    middleware.findIssuer({
      relationships: true,
      where: {systemId: ['system', 'id']},
    }),
    getIssuerClass,
  ])
  server.get('/public/systems/:systemSlug/issuers/:issuerSlug/programs/:programSlug', [
    middleware.findSystem(),
    middleware.findIssuer({where: {systemId: ['system', 'id']}}),
    middleware.findProgram({
      relationships: true,
      where: {issuerId: ['issuer', 'id']},
    }),
    getIssuerClass,
  ])
  function getIssuerClass(req, res, next) {
    return res.send(200, makeIssuerOrganization(
      req.program, req.issuer, req.system
    ))
  }
  function makeIssuerOrganization(program, issuer, system) {
    const lookup = findFirstKeyIn([program, issuer, system])
    return {
      name: lookup('name'),
      url: lookup('url'),
      description: lookup('description'),
      email: lookup('email'),
    }
  }
  function findFirstKeyIn(things) {
    things = things.map(function (o) { return o || {} })
    return function lookup(key) {
      for (var i = 0; i < things.length; i++)
        if (things[i][key]) return things[i][key]
    }
  }
}
