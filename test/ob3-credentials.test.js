// Tests for Task 7: signing + status list + GET /public/credentials/* +
// credentialUrl in POST responses/webhooks — plus the post-review fixes:
// mandatory PUBLIC_BASE_URL (no Host-header-derived signing), byte-stable
// concurrency, AJV validation of the SERVED (signed) credential, and the
// `application/vc+ld+json` Accept header actually being acceptable.
//
// Uses spawn(app) like test/badge-instances.test.js/test/did-document.test.js
// — NODE_ENV=test bypasses auth, and `/public/` is auth-exempt anyway (see
// app/lib/middleware.js#verifyRequest()). The signing key is generated on
// the fly (same pattern as test/issuer-key.test.js/test/did-document.test.js)
// — never read from a real env var, never hardcoded.
//
// Focused run:
//   NODE_ENV=test DB_HOST=127.0.0.1 DB_USER=badges DB_PASSWORD=badges \
//     DB_NAME=badgekit_test npx tap --no-coverage test/ob3-credentials.test.js
const test = require('tap').test
const http = require('http')
const url = require('url')
const concat = require('concat-stream')
const Ajv2019 = require('ajv/dist/2019')
const addFormats = require('ajv-formats')
const schema = require('../vendor/ob3/ob_v3p0_achievementcredential_schema.json')
const app = require('../')
const spawn = require('./spawn')
const startWebhookServer = require('./test-webhook-server')
const BadgeInstances = require('../app/models/badge-instance')
const makeDocumentLoader = require('../app/lib/document-loader')
const logger = require('../app/lib/logger')

const ajv = new Ajv2019({ strict: false })
addFormats(ajv)
const validateSchema = ajv.compile(schema)

const DID = 'did:web:localhost%3A8080'
// Deliberately NOT derived from spawn()'s ephemeral port — this is the whole
// point of the CRITICAL fix: signed credentials must be baked with an
// operator-chosen base URL, never the request's (spoofable) Host header.
const PUBLIC_BASE_URL = 'http://localhost:8080'

function generateTestSigningKey (did) {
  return import('@digitalbazaar/ed25519-multikey').then(function (multikey) {
    return multikey.generate({ id: did + '#key-0', controller: did })
  }).then(function (keyPair) {
    return keyPair.export({ publicKey: true, secretKey: true, canonicalize: true })
  })
}

// Raw fetch (not spawn.js's JSON.parse-everything requester) — needed to
// assert byte-for-byte identity of the served credential across GETs, to
// check the exact Content-Type header, to set an arbitrary Accept header,
// and to spoof a Host header (regression test for the CRITICAL fix).
function rawGet (fullUrl, headers) {
  return new Promise(function (resolve, reject) {
    http.get(fullUrl, { headers: headers || {} }, function (res) {
      var chunks = []
      res.on('data', function (chunk) { chunks.push(chunk) })
      res.on('end', function () {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        })
      })
      res.on('error', reject)
    }).on('error', reject)
  })
}

function loadVerifierDeps () {
  return Promise.all([
    import('@digitalbazaar/vc'),
    import('@digitalbazaar/data-integrity'),
    import('@digitalbazaar/eddsa-rdfc-2022-cryptosuite'),
  ]).then(function (mods) {
    return { vc: mods[0], DataIntegrityProof: mods[1].DataIntegrityProof, cryptosuite: mods[2].cryptosuite }
  })
}

// Independent verification (spec §7.4): a real vc.verifyCredential() round
// trip against the SAME pinned documentLoader the app itself uses — not a
// hand-rolled signature check. `checkStatus` is a stub that always reports
// "not revoked": the OpenBadgeCredential's `credentialStatus` property
// requires @digitalbazaar/vc to be given one, but Task 7 is only pinning the
// proof-cryptography round trip here, not revocation-list lookups.
function verifyCredential (credential) {
  return loadVerifierDeps().then(function (deps) {
    const suite = new deps.DataIntegrityProof({ cryptosuite: deps.cryptosuite })
    const documentLoader = makeDocumentLoader()
    const checkStatus = function () { return Promise.resolve({ verified: true }) }
    return deps.vc.verifyCredential({ credential: credential, suite: suite, documentLoader: documentLoader, checkStatus: checkStatus })
  })
}

delete process.env.ISSUER_SIGNING_KEY
delete process.env.ISSUER_DID
delete process.env.PUBLIC_BASE_URL

spawn(app).then(function (api) {
  test('ob3-credentials: nothing configured -> 503 SigningNotConfigured (both routes, routes still registered)', function (t) {
    api.get('/public/credentials/whatevs').then(function (res) {
      t.same(res.statusCode, 503, 'credential route: 503')
      t.same(res.body.code, 'SigningNotConfigured')
      return api.get('/public/credentials/status/0')
    }).then(function (res) {
      t.same(res.statusCode, 503, 'status list route: 503')
      t.same(res.body.code, 'SigningNotConfigured')
      t.end()
    }).catch(api.fail(t))
  })

  test('ob3-credentials: issuer key configured, PUBLIC_BASE_URL still unset -> 503 naming PUBLIC_BASE_URL (CRITICAL fix coverage)', function (t) {
    generateTestSigningKey(DID).then(function (exported) {
      process.env.ISSUER_DID = DID
      process.env.ISSUER_SIGNING_KEY = exported.secretKeyMultibase
      // PUBLIC_BASE_URL is deliberately still unset here.
      return api.get('/public/credentials/whatevs')
    }).then(function (res) {
      t.same(res.statusCode, 503, 'credential route: 503 even though the issuer key IS configured')
      t.same(res.body.code, 'SigningNotConfigured')
      t.match(res.body.message, /PUBLIC_BASE_URL/, 'message names PUBLIC_BASE_URL specifically')
      return api.get('/public/credentials/status/0')
    }).then(function (res) {
      t.same(res.statusCode, 503, 'status list route: 503 too')
      t.match(res.body.message, /PUBLIC_BASE_URL/, 'message names PUBLIC_BASE_URL specifically')
      t.end()
    }).catch(t.threw)
  })

  test('ob3-credentials: configure PUBLIC_BASE_URL — signing routes fully enabled for the rest of this file', function (t) {
    process.env.PUBLIC_BASE_URL = PUBLIC_BASE_URL
    t.end()
  })

  // F3 (final whole-plan review): a coherence guard between ISSUER_DID and
  // PUBLIC_BASE_URL — both are "configured" here (each passes its own
  // isConfigured()/getConfiguredBaseUrl() check individually), but they name
  // DIFFERENT hosts, which must still 503 rather than silently sign
  // credentials whose issuer identity (did:web host) and content host
  // (PUBLIC_BASE_URL) permanently diverge.
  test('ob3-credentials: F3 — ISSUER_DID / PUBLIC_BASE_URL host mismatch -> 503 SigningNotConfigured naming both', function (t) {
    const mismatchedDid = 'did:web:not-the-same-host.example.org'
    const originalDid = process.env.ISSUER_DID
    const originalSigningKey = process.env.ISSUER_SIGNING_KEY

    generateTestSigningKey(mismatchedDid).then(function (exported) {
      process.env.ISSUER_DID = mismatchedDid
      process.env.ISSUER_SIGNING_KEY = exported.secretKeyMultibase
      return api.get('/public/credentials/whatevs')
    }).then(function (res) {
      t.same(res.statusCode, 503, 'credential route: 503 on host mismatch')
      t.same(res.body.code, 'SigningNotConfigured')
      t.match(res.body.message, /not-the-same-host\.example\.org/, 'message names the ISSUER_DID host')
      t.match(res.body.message, /localhost:8080/, 'message names the PUBLIC_BASE_URL host')
      return api.get('/public/credentials/status/0')
    }).then(function (res) {
      t.same(res.statusCode, 503, 'status list route: 503 on host mismatch too')
      t.same(res.body.code, 'SigningNotConfigured')
      t.match(res.body.message, /not-the-same-host\.example\.org/, 'message names the ISSUER_DID host')
      t.match(res.body.message, /localhost:8080/, 'message names the PUBLIC_BASE_URL host')

      // Restore coherence — ISSUER_DID and PUBLIC_BASE_URL must agree again
      // for the rest of this file.
      process.env.ISSUER_DID = originalDid
      process.env.ISSUER_SIGNING_KEY = originalSigningKey
      t.end()
    }).catch(t.threw)
  })

  test('ob3-credentials: CRITICAL FIX regression — a spoofed Host header never ends up baked into the signed credential', function (t) {
    const email = 'brian-ob3-host-spoof@example.org'
    var slug

    api.post('/systems/chicago/badges/chicago-badge/instances', { email: email }).then(function (res) {
      t.same(res.statusCode, 201)
      slug = res.body.instance.slug
      // First-ever GET for this instance (lazy sign happens right here) is
      // made with an attacker-controlled Host header, pointed at the actual
      // spawned server (same as a real request would be) but claiming to be
      // a different host entirely.
      return rawGet(api.makeUrl('/public/credentials/' + slug), { Host: 'evil.example.org' })
    }).then(function (res) {
      t.same(res.statusCode, 200)
      const credential = JSON.parse(res.body)
      t.match(credential.id, /^http:\/\/localhost:8080\//, 'credential.id is PUBLIC_BASE_URL-derived, not Host-derived')
      t.notMatch(credential.id, /evil\.example\.org/, 'the spoofed Host never appears in credential.id')
      t.match(credential.credentialSubject.achievement.id, /^http:\/\/localhost:8080\//, 'achievement.id is PUBLIC_BASE_URL-derived too')
      t.notMatch(JSON.stringify(credential), /evil\.example\.org/, 'the spoofed Host appears NOWHERE in the signed document')
      t.end()
    }).catch(t.threw)
  })

  test('ob3-credentials: GET /public/credentials/:slug — signs (lazy), verifies, is byte-stable, schema-valid', function (t) {
    const credentialUrl = api.makeUrl('/public/credentials/whatevs')
    var firstRawBody
    var instanceId

    BadgeInstances.getOne({ slug: 'whatevs' }).then(function (before) {
      t.same(before.credential, null, 'starts unsigned (NULL credential column), per test-data.sql')
      instanceId = before.id
      return rawGet(credentialUrl)
    }).then(function (first) {
      t.same(first.statusCode, 200, '200 on first GET (lazy sign)')
      t.match(first.headers['content-type'], /application\/vc\+ld\+json/, 'Content-Type is application/vc+ld+json')
      firstRawBody = first.body

      const credential = JSON.parse(first.body)

      // I4: validate the actual SERVED (signed) credential, not just the
      // unsigned builder output (already covered by test/ob3-builder.test.js).
      const valid = validateSchema(credential)
      t.ok(valid, 'served credential is schema-valid: ' + JSON.stringify(validateSchema.errors))
      t.same(credential['@context'], [
        'https://www.w3.org/ns/credentials/v2',
        'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',
      ], '@context is still the exact ordered pair on the SIGNED document')
      t.same(credential.credentialSchema[0]['@context'], {
        '1EdTechJsonSchemaValidator2019':
          'https://purl.imsglobal.org/spec/ob/v3p0#1EdTechJsonSchemaValidator2019',
      }, 'credentialSchema[0] carries the scoped inline @context that fixes the relative-@type safe-mode failure')
      t.same(credential.id, PUBLIC_BASE_URL + '/public/credentials/whatevs',
        'credential.id matches the PUBLIC_BASE_URL-derived URL (not the actual request URL/port)')

      // F2 (final whole-plan review): the shard/index are COMPUTED from the
      // instance's real id, not hardcoded — this instance's id is < 131072
      // (test fixtures never approach the ceiling), so it lands in shard 0,
      // but the assertion is built from `instanceId`, not a literal '0', so
      // it would actually catch a regression to the pre-sharding hardcoded
      // `/status/0` behavior just as well as it confirms today's value.
      const expectedShard = Math.floor(instanceId / 131072)
      const expectedIndex = String(instanceId % 131072)
      const expectedStatusListCredential = PUBLIC_BASE_URL + '/public/credentials/status/' + expectedShard
      t.same(credential.credentialStatus.statusListCredential, expectedStatusListCredential,
        'credentialStatus.statusListCredential is derived from the instance id\'s shard')
      t.same(credential.credentialStatus.statusListIndex, expectedIndex,
        'credentialStatus.statusListIndex is instanceId % 131072, not the raw id')
      t.same(credential.credentialStatus.id, expectedStatusListCredential + '#' + instanceId)

      t.ok(credential.proof, 'has a proof')
      t.same(credential.proof.cryptosuite, 'eddsa-rdfc-2022')
      t.same(credential.proof.verificationMethod, DID + '#key-0')
      t.same(credential.proof.type, 'DataIntegrityProof')

      return verifyCredential(credential)
    }).then(function (result) {
      t.same(result.verified, true, 'a real vc.verifyCredential() round trip verifies (documentLoader is the real pinned one)')

      return BadgeInstances.getOne({ slug: 'whatevs' })
    }).then(function (persisted) {
      t.ok(persisted.credential, 'lazily persisted into the credential column')
      t.same(persisted.credential, firstRawBody, 'persisted column is exactly the served body')

      const tampered = JSON.parse(persisted.credential)
      tampered.name = 'TAMPERED NAME'
      return verifyCredential(tampered)
    }).then(function (result) {
      t.same(result.verified, false, 'altering a signed field breaks verification')

      return rawGet(credentialUrl)
    }).then(function (second) {
      t.same(second.statusCode, 200, '200 on second GET (already signed)')
      t.same(second.body, firstRawBody, 'second GET is byte-identical to the first (served from storage, verbatim)')
      t.end()
    }).catch(t.threw)
  })

  test('ob3-credentials: I3 — two concurrent first-GETs on a never-signed instance converge on byte-identical bytes', function (t) {
    const email = 'brian-ob3-concurrent@example.org'

    api.post('/systems/chicago/badges/chicago-badge/instances', { email: email }).then(function (res) {
      t.same(res.statusCode, 201)
      const slug = res.body.instance.slug
      const credentialUrl = api.makeUrl('/public/credentials/' + slug)

      // Fire both requests before either has a chance to complete.
      return Promise.all([rawGet(credentialUrl), rawGet(credentialUrl)]).then(function (results) {
        return { slug: slug, results: results }
      })
    }).then(function (ctx) {
      const a = ctx.results[0]
      const b = ctx.results[1]
      t.same(a.statusCode, 200)
      t.same(b.statusCode, 200)
      t.same(a.body, b.body, 'both concurrent responses are byte-identical to each other')

      return BadgeInstances.getOne({ slug: ctx.slug }).then(function (persisted) {
        t.same(persisted.credential, a.body, 'the row that ends up persisted matches exactly what both requests were served')
        t.end()
      })
    }).catch(t.threw)
  })

  test('ob3-credentials: GET /public/credentials/status/0 — signed BitstringStatusListCredential, memoized', function (t) {
    const statusUrl = api.makeUrl('/public/credentials/status/0')
    var firstRawBody

    rawGet(statusUrl).then(function (first) {
      t.same(first.statusCode, 200)
      t.match(first.headers['content-type'], /application\/vc\+ld\+json/)
      firstRawBody = first.body

      const credential = JSON.parse(first.body)
      t.ok(credential.type.indexOf('BitstringStatusListCredential') !== -1, 'type includes BitstringStatusListCredential')
      t.ok(credential.type.indexOf('VerifiableCredential') !== -1)
      t.same(credential.credentialSubject.type, 'BitstringStatusList')
      t.same(credential.credentialSubject.statusPurpose, 'revocation')
      t.ok(credential.credentialSubject.encodedList && credential.credentialSubject.encodedList.length > 0, 'encodedList is non-empty')
      t.match(credential.credentialSubject.encodedList, /^u/, 'multibase base64url prefix')
      t.same(credential.id, PUBLIC_BASE_URL + '/public/credentials/status/0')
      t.ok(credential.proof, 'has a proof')

      return verifyCredential(credential)
    }).then(function (result) {
      t.same(result.verified, true, 'status list credential proof verifies')
      return rawGet(statusUrl)
    }).then(function (second) {
      t.same(second.statusCode, 200)
      t.same(second.body, firstRawBody, 'memoized per baseUrl — second GET is byte-identical to the first')
      t.end()
    }).catch(t.threw)
  })

  // F2 (final whole-plan review): the shard route parameter must be a
  // canonical non-negative integer. Anything else (non-numeric, negative,
  // leading zeros) can never correspond to a real shard, so it 404s — this
  // must hold true regardless of whether signing is otherwise configured,
  // since it's a structural property of the URL, not a configuration state.
  test('ob3-credentials: F2 — invalid status list shard params 404 (not 503, not 200)', function (t) {
    Promise.all([
      api.get('/public/credentials/status/abc'),
      api.get('/public/credentials/status/-1'),
      api.get('/public/credentials/status/007'),
      api.get('/public/credentials/status/1.5'),
    ]).then(function (results) {
      results.forEach(function (res, i) {
        t.same(res.statusCode, 404, 'invalid shard #' + i + ' -> 404')
      })
      t.end()
    }).catch(api.fail(t))
  })

  // Post-final-review fix: a WELL-FORMED shard (passes SHARD_PARAM_PATTERN)
  // must still 404 once it's beyond what real data could ever justify —
  // otherwise any anonymous caller could force an unbounded number of fresh
  // Ed25519 signs and forever-retained ob3-signer.js Map entries just by
  // incrementing a URL segment (no auth required on /public/ routes at all).
  // This test file's fixture ids are all tiny, so maxShard is 0 throughout —
  // shard 1 is a well-formed but nonexistent shard here, and must 404 both
  // times it's requested (not sign-then-serve on some later attempt, and
  // not fail once then succeed from a stale memo).
  test('ob3-credentials: F2 (post-review) — a well-formed shard beyond real data 404s, every time, never signs', function (t) {
    const beyondUrl = api.makeUrl('/public/credentials/status/1')

    api.get('/public/credentials/status/1').then(function (first) {
      t.same(first.statusCode, 404, 'shard 1 is well-formed but no instance id justifies it yet -> 404')
      return rawGet(beyondUrl)
    }).then(function (second) {
      t.same(second.statusCode, 404, 'requesting it again still 404s — no memo entry was created for it')
      // Shard 0 must remain unaffected by an out-of-bounds sibling request.
      return api.get('/public/credentials/status/0')
    }).then(function (stillFine) {
      t.same(stillFine.statusCode, 200, 'shard 0 (the only shard real data justifies) is still servable')
      t.end()
    }).catch(api.fail(t))
  })

  test('ob3-credentials: I5 — Accept: application/vc+ld+json is acceptable, not a 406', function (t) {
    Promise.all([
      rawGet(api.makeUrl('/public/credentials/whatevs'), { Accept: 'application/vc+ld+json' }),
      rawGet(api.makeUrl('/public/credentials/status/0'), { Accept: 'application/vc+ld+json' }),
    ]).then(function (results) {
      t.same(results[0].statusCode, 200, 'credential route accepts Accept: application/vc+ld+json')
      t.same(results[1].statusCode, 200, 'status list route accepts Accept: application/vc+ld+json')
      t.end()
    }).catch(t.threw)
  })

  test('ob3-credentials: missing instance -> 404', function (t) {
    api.get('/public/credentials/does-not-exist-at-all').then(function (res) {
      t.same(res.statusCode, 404)
      t.end()
    }).catch(api.fail(t))
  })

  test('ob3-credentials: POST single instance — response + webhook both include credentialUrl next to assertionUrl', function (t) {
    const secret = 'ob3.shhh.very.secret'
    const email = 'brian-ob3-webhook@example.org'

    startWebhookServer({ systemId: 1, secret: secret }).then(function (server) {
      server.once('request', function (req, res) {
        req.setEncoding('utf8')
        req.pipe(concat(function (body) {
          res.end('ok')
          server.close()

          const hookData = JSON.parse(body)
          t.ok(hookData.assertionUrl, 'webhook payload still has assertionUrl')
          t.ok(hookData.credentialUrl, 'webhook payload also has credentialUrl')
          t.ok(/^\/public\/credentials\/[0-9a-f]+$/.test(url.parse(hookData.credentialUrl).pathname),
            'properly formed credential url')
          t.end()
        }))
      })

      return api.post('/systems/chicago/badges/chicago-badge/instances', { email: email }).then(function (res) {
        t.same(res.statusCode, 201)
        const instance = res.body.instance
        t.ok(instance.assertionUrl, 'response instance still has assertionUrl')
        t.ok(instance.credentialUrl, 'response instance also has credentialUrl')
        t.same(url.parse(instance.credentialUrl).pathname, '/public/credentials/' + instance.slug)
      })
    }).catch(api.fail(t))
  })

  test('ob3-credentials: POST bulk instances — every created instance gets credentialUrl too', function (t) {
    const emails = ['brian-ob3-bulk-1@example.org', 'brian-ob3-bulk-2@example.org']

    api.post('/systems/chicago/badges/chicago-badge/instances/bulk', { emails: emails }).then(function (res) {
      t.same(res.statusCode, 201)
      t.same(res.body.instances.length, 2)
      res.body.instances.forEach(function (instance) {
        t.ok(instance.assertionUrl, 'bulk-created instance has assertionUrl')
        t.ok(instance.credentialUrl, 'bulk-created instance also has credentialUrl')
        t.same(url.parse(instance.credentialUrl).pathname, '/public/credentials/' + instance.slug)
      })
      t.end()
    }).catch(api.fail(t))
  })

  test('ob3-credentials: deleted instance -> credential GET 404s too', function (t) {
    const email = 'brian-ob3-delete-me@example.org'
    var slug

    api.post('/systems/chicago/badges/chicago-badge/instances', { email: email }).then(function (res) {
      t.same(res.statusCode, 201)
      slug = res.body.instance.slug
      return api.get('/public/credentials/' + slug)
    }).then(function (res) {
      t.same(res.statusCode, 200, 'credential is servable (and gets signed) before deletion')
      return api.del('/systems/chicago/badges/chicago-badge/instances/' + email)
    }).then(function (res) {
      t.same(res.statusCode, 200, 'instance deleted')
      return api.get('/public/credentials/' + slug)
    }).then(function (res) {
      t.same(res.statusCode, 404, 'credential 404s once the instance is gone')
      t.end()
    }).catch(api.fail(t))
  })

  // F3 (final whole-plan review): a credential SIGNED under an old
  // PUBLIC_BASE_URL/ISSUER_DID pair (before a domain move) must still be
  // served byte-stably under the new one — never silently re-signed/rewritten
  // — but a warning should be logged so the mismatch doesn't go unnoticed.
  // Simulates a domain move: signs an instance under an "old" (but
  // internally-coherent) base URL/DID pair, then switches back to this
  // file's standard PUBLIC_BASE_URL/ISSUER_DID and re-fetches the SAME
  // credential, asserting: still 200, still byte-identical (not re-signed),
  // and a req.log.warn() call happened naming the stale id.
  test('ob3-credentials: F3 — GET of a credential stored under an old PUBLIC_BASE_URL still 200s byte-stably, and logs a warning', function (t) {
    const oldBaseUrl = 'http://old-domain.example.org'
    const oldDid = 'did:web:old-domain.example.org'
    const email = 'brian-ob3-old-base@example.org'
    const originalBaseUrl = process.env.PUBLIC_BASE_URL
    const originalDid = process.env.ISSUER_DID
    const originalSigningKey = process.env.ISSUER_SIGNING_KEY
    var slug
    var oldRawBody

    generateTestSigningKey(oldDid).then(function (exported) {
      // Sign under the "old" domain — internally coherent (oldDid's host
      // matches oldBaseUrl's host), just different from what the rest of
      // this file uses.
      process.env.PUBLIC_BASE_URL = oldBaseUrl
      process.env.ISSUER_DID = oldDid
      process.env.ISSUER_SIGNING_KEY = exported.secretKeyMultibase

      return api.post('/systems/chicago/badges/chicago-badge/instances', { email: email })
    }).then(function (res) {
      t.same(res.statusCode, 201)
      slug = res.body.instance.slug
      return rawGet(api.makeUrl('/public/credentials/' + slug))
    }).then(function (first) {
      t.same(first.statusCode, 200, 'signs fine under the old base URL')
      oldRawBody = first.body
      t.match(JSON.parse(oldRawBody).id, /^http:\/\/old-domain\.example\.org\//,
        'credential.id is baked with the OLD base URL')

      // "Domain move": restore the standard, coherent PUBLIC_BASE_URL/
      // ISSUER_DID pair used by the rest of this file.
      process.env.PUBLIC_BASE_URL = originalBaseUrl
      process.env.ISSUER_DID = originalDid
      process.env.ISSUER_SIGNING_KEY = originalSigningKey

      var warnCalls = []
      var originalWarn = logger.warn
      logger.warn = function () {
        warnCalls.push(Array.prototype.slice.call(arguments))
        return originalWarn.apply(logger, arguments)
      }

      return rawGet(api.makeUrl('/public/credentials/' + slug)).then(function (second) {
        logger.warn = originalWarn
        return { second: second, warnCalls: warnCalls }
      })
    }).then(function (result) {
      const second = result.second
      t.same(second.statusCode, 200, 'still 200 under the NEW base URL — served, not rejected')
      t.same(second.body, oldRawBody, 'byte-identical to what was stored — NOT re-signed under the new base URL')

      const warned = result.warnCalls.some(function (args) {
        return args.some(function (arg) {
          return typeof arg === 'string' && arg.indexOf('old-domain.example.org') !== -1
        }) || args.some(function (arg) {
          return arg && typeof arg === 'object' && JSON.stringify(arg).indexOf('old-domain.example.org') !== -1
        })
      })
      t.ok(warned, 'req.log.warn() was called naming the stale (old-base) credential id')
      t.end()
    }).catch(t.threw)
  })

  test(':cleanup:', function (t) {
    delete process.env.ISSUER_SIGNING_KEY
    delete process.env.ISSUER_DID
    delete process.env.PUBLIC_BASE_URL
    api.done()
    t.end()
  })
})
