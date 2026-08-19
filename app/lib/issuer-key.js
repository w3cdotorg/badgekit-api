// Loads the OB 3.0 issuer signing key (Ed25519 / Multikey) from the
// environment.
//
// Env vars:
//   ISSUER_DID          e.g. "did:web:localhost%3A8080"
//   ISSUER_SIGNING_KEY   a canonical Ed25519 secretKeyMultibase string
//                        (multibase base58-btc, 32-byte seed) — see
//                        bin/generate-issuer-key.js. Never stored in the DB,
//                        the image, or the repo.
//
// @digitalbazaar/ed25519-multikey and base58-universal are ESM-only while
// this repo is CommonJS, so both are loaded with memoized dynamic imports.
//
// Note on the key format: @digitalbazaar/ed25519-multikey's `from()` always
// requires an explicit `publicKeyMultibase` — it will not derive the public
// key from a secretKeyMultibase alone. Since ISSUER_SIGNING_KEY only carries
// the canonical (32-byte seed) secretKeyMultibase, we decode it ourselves
// (strip the multibase 'z' + the ed25519-priv multicodec header) to recover
// the raw seed, then hand that seed to `generate()`, which is the library's
// public, documented way to deterministically rebuild the same key pair
// (including the public key) from a seed.

var ed25519MultikeyPromise = null
var base58Promise = null

function loadEd25519Multikey () {
  if (!ed25519MultikeyPromise) {
    ed25519MultikeyPromise = import('@digitalbazaar/ed25519-multikey')
    ed25519MultikeyPromise.catch(function () { ed25519MultikeyPromise = null })
  }
  return ed25519MultikeyPromise
}

function loadBase58 () {
  if (!base58Promise) {
    base58Promise = import('base58-universal')
    base58Promise.catch(function () { base58Promise = null })
  }
  return base58Promise
}

// multicodec ed25519-priv header, as used by @digitalbazaar/ed25519-multikey
var MULTICODEC_PRIV_HEADER_LENGTH = 2
var SEED_LENGTH = 32

function decodeSeed (secretKeyMultibase, base58) {
  if (typeof secretKeyMultibase !== 'string' || secretKeyMultibase[0] !== 'z') {
    throw new Error('ISSUER_SIGNING_KEY must be a multibase (base58-btc) encoded string')
  }
  var decoded = base58.decode(secretKeyMultibase.slice(1))
  var seed = decoded.slice(MULTICODEC_PRIV_HEADER_LENGTH)
  if (seed.length !== SEED_LENGTH) {
    throw new Error('ISSUER_SIGNING_KEY must decode to a 32-byte Ed25519 seed')
  }
  return seed
}

function isConfigured () {
  return !!(process.env.ISSUER_SIGNING_KEY && process.env.ISSUER_DID)
}

function getDid () {
  return process.env.ISSUER_DID
}

// F3 (final whole-plan review): a did:web identifier encodes the host (and
// optional port) it resolves against directly in the identifier itself —
// "did:web:example.com" resolves to https://example.com/.well-known/did.json,
// "did:web:localhost%3A8080" (colon percent-encoded, per the did:web method
// spec) resolves to http://localhost:8080/.well-known/did.json. Everything
// this service signs asserts `issuer.id` = ISSUER_DID, so if that host
// doesn't agree with PUBLIC_BASE_URL (the host baked into every credential
// `id`/`achievement.id`/etc.), credentials get signed whose issuer identity
// and content host silently diverge — permanently, since credentials are
// immutable once issued. Extracts just the host[:port] segment: everything
// between "did:web:" and the next unencoded ':' (later colon-delimited
// segments are did:web PATH components, not part of the host) with %XX
// percent-encoding decoded back to literal characters.
function getDidHost () {
  var did = getDid()
  if (typeof did !== 'string' || did.indexOf('did:web:') !== 0) return null
  var rest = did.slice('did:web:'.length)
  var hostSegment = rest.split(':')[0]
  if (!hostSegment) return null
  try {
    return decodeURIComponent(hostSegment)
  } catch (e) {
    return null
  }
}

var keyPairPromise = null

function getKeyPair () {
  if (!isConfigured()) {
    return Promise.reject(new Error('ISSUER_SIGNING_KEY / ISSUER_DID not configured'))
  }
  if (!keyPairPromise) {
    var did = getDid()
    var secretKeyMultibase = process.env.ISSUER_SIGNING_KEY
    keyPairPromise = Promise.all([loadEd25519Multikey(), loadBase58()]).then(function (mods) {
      var multikey = mods[0]
      var base58 = mods[1]
      var seed = decodeSeed(secretKeyMultibase, base58)
      return multikey.generate({
        id: did + '#key-0',
        controller: did,
        seed: seed,
      })
    })
    keyPairPromise.catch(function () { keyPairPromise = null })
  }
  return keyPairPromise
}

function getDidDocument () {
  return getKeyPair().then(function (keyPair) {
    return keyPair.export({ publicKey: true })
  }).then(function (publicKey) {
    var did = getDid()
    return {
      // INVARIANT: did/v1 MUST stay first in this array — app/lib/
      // document-loader.js's network-freedom relies on jsonld-signatures'
      // ControllerProofPurpose#validate() "mustFrame" optimization, which
      // only skips jsonld.frame() (and so only avoids dereferencing this
      // @context) when this array's first element is exactly did/v1. See
      // that file's header comment and vendor/ob3/README.md for the
      // reproduction proving this.
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1',
      ],
      id: did,
      verificationMethod: [{
        id: did + '#key-0',
        type: 'Multikey',
        controller: did,
        publicKeyMultibase: publicKey.publicKeyMultibase,
      }],
      assertionMethod: [did + '#key-0'],
    }
  })
}

module.exports = {
  isConfigured: isConfigured,
  getDid: getDid,
  getDidHost: getDidHost,
  getKeyPair: getKeyPair,
  getDidDocument: getDidDocument,
}
