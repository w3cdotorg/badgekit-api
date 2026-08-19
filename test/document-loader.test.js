// Tests for app/lib/document-loader.js — the pinned JSON-LD documentLoader
// consumed by @digitalbazaar/vc (Task 7). It must NEVER touch the network:
// every context it can resolve is vendored on disk under vendor/ob3/, and
// the local issuer identity (did document + verificationMethod) is resolved
// via app/lib/issuer-key.js. Any other URL is rejected.
//
// Verified empirically (see task-6-report.md) against a real
// @digitalbazaar/vc sign()+verify() round trip that the DID/security
// contexts (https://www.w3.org/ns/did/v1, https://w3id.org/security/
// multikey/v1) are NEVER requested by that flow — the DID document and the
// verificationMethod object are consumed directly (no jsonld expansion of
// their own @context), so those two contexts are intentionally NOT vendored
// here. Also verified: the verificationMethod URL (`ISSUER_DID#key-0`) must
// resolve to the verificationMethod object itself (the individual Multikey),
// NOT the full DID document — @digitalbazaar/ed25519-multikey's from() /
// eddsa-rdfc-2022-cryptosuite's createVerifier() require a top-level
// `publicKeyMultibase`, which only the verificationMethod object has.
var test = require('tap').test

var CREDENTIALS_V2_URL = 'https://www.w3.org/ns/credentials/v2'
var OB_CONTEXT_URL = 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'

// Same throwaway-key pattern as test/issuer-key.test.js — never read from an
// external env var, never hardcoded.
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

test('document-loader: serves the VC Data Model 2.0 context from disk', function (t) {
  var makeDocumentLoader = require('../app/lib/document-loader')
  var loader = makeDocumentLoader()

  loader(CREDENTIALS_V2_URL).then(function (result) {
    t.equal(result.documentUrl, CREDENTIALS_V2_URL, 'documentUrl echoes the requested url')
    t.equal(result.contextUrl, null, 'contextUrl is null (no redirect)')
    t.ok(result.document, 'document is present')
    t.equal(result.document['@context']['@protected'], true,
      'known field: the vendored VC v2 context is @protected')
    t.end()
  }).catch(t.threw)
})

test('document-loader: serves the OB 3.0 context from disk', function (t) {
  var makeDocumentLoader = require('../app/lib/document-loader')
  var loader = makeDocumentLoader()

  loader(OB_CONTEXT_URL).then(function (result) {
    t.equal(result.documentUrl, OB_CONTEXT_URL, 'documentUrl echoes the requested url')
    t.equal(result.contextUrl, null, 'contextUrl is null (no redirect)')
    t.ok(result.document, 'document is present')
    t.ok(result.document['@context']['OpenBadgeCredential'],
      'known field: the vendored OB context defines the OpenBadgeCredential term')
    t.end()
  }).catch(t.threw)
})

test('document-loader: resolves the local issuer DID document', function (t) {
  var did = 'did:web:localhost%3A8080'

  generateTestSigningKey(did).then(function (generated) {
    process.env.ISSUER_DID = did
    process.env.ISSUER_SIGNING_KEY = generated.secretKeyMultibase
    delete require.cache[require.resolve('../app/lib/issuer-key')]
    delete require.cache[require.resolve('../app/lib/document-loader')]
    var makeDocumentLoader = require('../app/lib/document-loader')
    var loader = makeDocumentLoader()

    return loader(did).then(function (result) {
      t.equal(result.documentUrl, did)
      t.equal(result.contextUrl, null)
      t.equal(result.document.id, did, 'document is the did document (id === did)')
      t.ok(Array.isArray(result.document.verificationMethod), 'has a verificationMethod array')
      t.equal(result.document.verificationMethod[0].publicKeyMultibase, generated.publicKeyMultibase,
        'exposes the same public key that was generated')
      t.end()
    })
  }).catch(t.threw)
})

test('document-loader: resolves the issuer verificationMethod (ISSUER_DID#key-0) to the key object, not the full did document', function (t) {
  var did = 'did:web:localhost%3A8080'

  generateTestSigningKey(did).then(function (generated) {
    process.env.ISSUER_DID = did
    process.env.ISSUER_SIGNING_KEY = generated.secretKeyMultibase
    delete require.cache[require.resolve('../app/lib/issuer-key')]
    delete require.cache[require.resolve('../app/lib/document-loader')]
    var makeDocumentLoader = require('../app/lib/document-loader')
    var loader = makeDocumentLoader()

    return loader(did + '#key-0').then(function (result) {
      t.equal(result.documentUrl, did + '#key-0')
      t.equal(result.contextUrl, null)
      t.equal(result.document.id, did + '#key-0')
      t.equal(result.document.type, 'Multikey', 'is the Multikey verificationMethod object itself')
      t.equal(result.document.controller, did)
      t.equal(result.document.publicKeyMultibase, generated.publicKeyMultibase,
        'exposes the same public key that was generated')
      t.notOk(result.document.verificationMethod,
        'is NOT the full did document (no nested verificationMethod array)')
      t.end()
    })
  }).catch(t.threw)
})

test('document-loader: rejects any other URL, naming it in the error, and never touches the network', function (t) {
  var makeDocumentLoader = require('../app/lib/document-loader')
  var loader = makeDocumentLoader()
  var evilUrl = 'https://example.org/evil'

  loader(evilUrl).then(function () {
    t.fail('should have rejected')
    t.end()
  }).catch(function (err) {
    t.ok(err instanceof Error, 'rejects with an Error')
    t.match(err.message, /pinned/, 'error message mentions "pinned"')
    t.ok(err.message.indexOf(evilUrl) !== -1, 'error message names the offending url')
    t.end()
  })
})

test('document-loader: rejects the DID/security contexts too (not vendored — never requested by the real sign/verify flow)', function (t) {
  var makeDocumentLoader = require('../app/lib/document-loader')
  var loader = makeDocumentLoader()

  Promise.all([
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/multikey/v1',
  ].map(function (url) {
    return loader(url).then(function () {
      t.fail('should have rejected ' + url)
    }).catch(function (err) {
      t.ok(err.message.indexOf(url) !== -1, 'names ' + url)
    })
  })).then(function () {
    t.end()
  })
})

test(':cleanup:', function (t) {
  delete process.env.ISSUER_SIGNING_KEY
  delete process.env.ISSUER_DID
  t.end()
})
