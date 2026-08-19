// Tests for Task 7: signing + status list + GET /public/credentials/* +
// credentialUrl in POST responses/webhooks.
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
const app = require('../')
const spawn = require('./spawn')
const startWebhookServer = require('./test-webhook-server')
const BadgeInstances = require('../app/models/badge-instance')
const makeDocumentLoader = require('../app/lib/document-loader')

const DID = 'did:web:localhost%3A8080'

function generateTestSigningKey (did) {
  return import('@digitalbazaar/ed25519-multikey').then(function (multikey) {
    return multikey.generate({ id: did + '#key-0', controller: did })
  }).then(function (keyPair) {
    return keyPair.export({ publicKey: true, secretKey: true, canonicalize: true })
  })
}

// Raw fetch (not spawn.js's JSON.parse-everything requester) — needed to
// assert byte-for-byte identity of the served credential across two GETs,
// and to check the exact Content-Type header.
function rawGet (fullUrl) {
  return new Promise(function (resolve, reject) {
    http.get(fullUrl, function (res) {
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

spawn(app).then(function (api) {
  test('ob3-credentials: signing not configured -> 503 SigningNotConfigured (both routes, route still registered)', function (t) {
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

  test('ob3-credentials: configure a throwaway signing key for the rest of this file', function (t) {
    generateTestSigningKey(DID).then(function (exported) {
      process.env.ISSUER_DID = DID
      process.env.ISSUER_SIGNING_KEY = exported.secretKeyMultibase
      t.end()
    }).catch(t.threw)
  })

  test('ob3-credentials: GET /public/credentials/:slug — signs (lazy), verifies, is byte-stable across GETs', function (t) {
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
      t.ok(credential.proof, 'has a proof')

      return verifyCredential(credential)
    }).then(function (result) {
      t.same(result.verified, true, 'status list credential proof verifies')
      return rawGet(statusUrl)
    }).then(function (second) {
      t.same(second.statusCode, 200)
      t.same(second.body, firstRawBody, 'memoized per process — second GET is byte-identical to the first')
      t.end()
    }).catch(t.threw)
  })

  test('ob3-credentials: missing instance -> 404', function (t) {
    api.get('/public/credentials/does-not-exist-at-all').then(function (res) {
      t.same(res.statusCode, 404)
      t.end()
    }).catch(api.fail(t))
  })

  test('ob3-credentials: POST instance response + webhook both include credentialUrl next to assertionUrl', function (t) {
    const secret = 'ob3.shhh.very.secret'
    const email = 'brian-ob3-webhook@example.org'

    startWebhookServer({ systemId: 1, secret: secret }).then(function (server) {
      server.once('request', function (req, res) {
        const concat = require('concat-stream')
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
        createdSlug = instance.slug
        t.ok(instance.assertionUrl, 'response instance still has assertionUrl')
        t.ok(instance.credentialUrl, 'response instance also has credentialUrl')
        t.same(url.parse(instance.credentialUrl).pathname, '/public/credentials/' + instance.slug)
      })
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
    api.done()
    t.end()
  })
})
