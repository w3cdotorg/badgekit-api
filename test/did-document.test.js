// Tests for GET /.well-known/did.json — OB 3.0 issuer DID document route.
//
// These tests cover the route's own behavior (503 vs 200, did document
// shape) via spawn(app), which requires NODE_ENV=test — under which
// middleware.js#verifyRequest() bypasses auth entirely, so it can't exercise
// the auth EXEMPTION itself. That exemption (no Authorization header still
// gets through to this route) IS covered — see the "GET /.well-known/did.json,
// should not 403 without auth" test in test/verify-request.test.js, which
// sets NODE_ENV to a non-'test' value ('auth-test', matching spawn.js's
// /test$/ requirement) so the real verifyRequest() logic runs. It's also
// checked manually via curl outside NODE_ENV=test in the task-2 report
// (Step 4).
const test = require('tap').test
const app = require('../')
const spawn = require('./spawn')

// Not configured first, then configured — a single spawn()/db connection is
// reused across both (spawn.js's db pool doesn't tolerate being spawned
// twice in the same process), and the route reads ISSUER_DID /
// ISSUER_SIGNING_KEY fresh from process.env on every request, so no
// require.cache reset is needed between the two scenarios.
delete process.env.ISSUER_SIGNING_KEY
delete process.env.ISSUER_DID

spawn(app).then(function (api) {

  test('did-document: not configured -> 503 SigningNotConfigured', function (t) {
    api.get('/.well-known/did.json').then(function (res) {
      t.same(res.statusCode, 503, 'should get 503')
      t.same(res.body.code, 'SigningNotConfigured', 'should have the right error code')
      t.end()
    }).catch(api.fail(t))
  })

  test('did-document: configured -> 200 did document', function (t) {
    var did = 'did:web:localhost%3A8080'

    import('@digitalbazaar/ed25519-multikey').then(function (multikey) {
      return multikey.generate({ id: did + '#key-0', controller: did })
    }).then(function (keyPair) {
      return keyPair.export({ publicKey: true, secretKey: true, canonicalize: true })
    }).then(function (exported) {
      process.env.ISSUER_DID = did
      process.env.ISSUER_SIGNING_KEY = exported.secretKeyMultibase

      return api.get('/.well-known/did.json').then(function (res) {
        t.same(res.statusCode, 200, 'should get 200')
        t.same(res.body.id, did, 'id should be the issuer did')
        t.same(res.body.verificationMethod[0].type, 'Multikey', 'verification method should be Multikey')
        t.same(res.body.verificationMethod[0].publicKeyMultibase, exported.publicKeyMultibase,
          'derived public key should match the one generated originally')
        t.end()
      })
    }).catch(function (err) {
      t.fail('Error: ' + err.message)
      t.end()
    })
  })

  test(':cleanup:', function (t) {
    delete process.env.ISSUER_SIGNING_KEY
    delete process.env.ISSUER_DID
    api.done()
    t.end()
  })
})
