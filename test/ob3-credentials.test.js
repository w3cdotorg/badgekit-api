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

    BadgeInstances.getOne({ slug: 'whatevs' }).then(function (before) {
      t.same(before.credential, null, 'starts unsigned (NULL credential column), per test-data.sql')
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

  test(':cleanup:', function (t) {
    delete process.env.ISSUER_SIGNING_KEY
    delete process.env.ISSUER_DID
    delete process.env.PUBLIC_BASE_URL
    api.done()
    t.end()
  })
})
