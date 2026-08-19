// Tests for app/lib/issuer-key.js — OB 3.0 issuer key loading.
//
// Controller ruling: the test signing key is generated on the fly, inside
// this file's own setup, using the same @digitalbazaar/ed25519-multikey lib
// the app code uses. It is never read from an external env var and never
// hardcoded in the repo.
var test = require('tap').test

// Builds a fresh, throwaway ISSUER_SIGNING_KEY value the same way
// bin/generate-issuer-key.js does: a canonical (32-byte seed) Ed25519
// secretKeyMultibase string. Also returns the ORIGINAL publicKeyMultibase
// (as computed at generation time, before any round-trip through
// ISSUER_SIGNING_KEY) so tests can assert the loader derives the exact same
// public key rather than merely "a" internally-consistent one.
function generateTestSigningKey (did) {
  return import('@digitalbazaar/ed25519-multikey').then(function (multikey) {
    return multikey.generate({ id: did + '#key-0', controller: did })
  }).then(function (keyPair) {
    return keyPair.export({ publicKey: true, secretKey: true, canonicalize: true })
  }).then(function (exported) {
    return {
      secretKeyMultibase: exported.secretKeyMultibase,
      publicKeyMultibase: exported.publicKeyMultibase,
    }
  })
}

test('issuer-key: not configured', function (t) {
  delete process.env.ISSUER_SIGNING_KEY
  delete process.env.ISSUER_DID
  delete require.cache[require.resolve('../app/lib/issuer-key')]
  var issuerKey = require('../app/lib/issuer-key')

  t.equal(issuerKey.isConfigured(), false, 'isConfigured() is false without env vars')

  issuerKey.getKeyPair().then(function () {
    t.fail('getKeyPair() should reject when not configured')
    t.end()
  }).catch(function (err) {
    t.ok(err instanceof Error, 'getKeyPair() rejects when not configured')
    t.end()
  })
})

test('issuer-key: configured → did document exposes the public key', function (t) {
  var did = 'did:web:localhost%3A8080'
  var originalPublicKeyMultibase

  generateTestSigningKey(did).then(function (generated) {
    originalPublicKeyMultibase = generated.publicKeyMultibase
    process.env.ISSUER_DID = did
    process.env.ISSUER_SIGNING_KEY = generated.secretKeyMultibase
    delete require.cache[require.resolve('../app/lib/issuer-key')]
    var issuerKey = require('../app/lib/issuer-key')

    t.equal(issuerKey.isConfigured(), true)
    t.equal(issuerKey.getDid(), did)

    return issuerKey.getDidDocument()
  }).then(function (doc) {
    t.equal(doc.id, 'did:web:localhost%3A8080')
    t.equal(doc.verificationMethod[0].id, 'did:web:localhost%3A8080#key-0')
    t.equal(doc.verificationMethod[0].type, 'Multikey')
    t.match(doc.verificationMethod[0].publicKeyMultibase, /^z/)
    // Critical: the loader must derive the SAME public key that was
    // generated originally — not merely a public key that happens to be
    // internally consistent with whatever it decoded (a wrong slice offset
    // on the secretKeyMultibase decode would still yield 32 bytes and a
    // valid-looking but DIFFERENT key pair).
    t.equal(doc.verificationMethod[0].publicKeyMultibase, originalPublicKeyMultibase,
      'derived public key matches the one generated originally, not just an internally-consistent one')
    t.same(doc.assertionMethod, ['did:web:localhost%3A8080#key-0'])
    t.end()
  }).catch(t.threw)
})

test('issuer-key: getKeyPair() returns a signer whose signature verifies', function (t) {
  var did = 'did:web:localhost%3A8080'

  generateTestSigningKey(did).then(function (generated) {
    process.env.ISSUER_DID = did
    process.env.ISSUER_SIGNING_KEY = generated.secretKeyMultibase
    delete require.cache[require.resolve('../app/lib/issuer-key')]
    var issuerKey = require('../app/lib/issuer-key')

    return issuerKey.getKeyPair()
  }).then(function (keyPair) {
    var signer = keyPair.signer()
    var data = new TextEncoder().encode('badgekit-api ob3 issuer-key test')
    return signer.sign({ data: data }).then(function (signature) {
      var verifier = keyPair.verifier()
      return verifier.verify({ data: data, signature: signature })
    })
  }).then(function (verified) {
    t.equal(verified, true, 'signature produced by the loaded key verifies')
    t.end()
  }).catch(t.threw)
})

test('issuer-key: getKeyPair() is memoized (same promise-backed key reused)', function (t) {
  var did = 'did:web:localhost%3A8080'

  generateTestSigningKey(did).then(function (generated) {
    process.env.ISSUER_DID = did
    process.env.ISSUER_SIGNING_KEY = generated.secretKeyMultibase
    delete require.cache[require.resolve('../app/lib/issuer-key')]
    var issuerKey = require('../app/lib/issuer-key')

    return Promise.all([issuerKey.getKeyPair(), issuerKey.getKeyPair()])
  }).then(function (pairs) {
    t.equal(pairs[0], pairs[1], 'getKeyPair() memoizes the loaded key pair')
    t.end()
  }).catch(t.threw)
})

test('issuer-key: getKeyPair() resets its memoized promise after a rejection, so a later valid key succeeds', function (t) {
  var did = 'did:web:localhost%3A8080'

  process.env.ISSUER_DID = did
  // Garbage that decodes (or fails to decode) but is not a usable key —
  // exercises the getKeyPair() rejection path and its `keyPairPromise = null`
  // reset.
  process.env.ISSUER_SIGNING_KEY = 'z-not-a-real-key'
  delete require.cache[require.resolve('../app/lib/issuer-key')]
  var issuerKey = require('../app/lib/issuer-key')

  issuerKey.getKeyPair().then(function () {
    t.fail('getKeyPair() should reject on a garbage ISSUER_SIGNING_KEY')
    t.end()
  }).catch(function (err) {
    t.ok(err instanceof Error, 'getKeyPair() rejects on a garbage ISSUER_SIGNING_KEY')

    // Same module instance (no require.cache reset), only the env var
    // changes — proves the memoized promise was cleared on rejection rather
    // than permanently poisoning the module.
    return generateTestSigningKey(did).then(function (generated) {
      process.env.ISSUER_SIGNING_KEY = generated.secretKeyMultibase
      return issuerKey.getKeyPair()
    })
  }).then(function (keyPair) {
    t.ok(keyPair, 'getKeyPair() resolves once a valid key is set, after a prior rejection')
    t.end()
  }).catch(t.threw)
})
