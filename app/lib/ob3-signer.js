// Task 7: signs unsigned OB 3.0 credentials (app/lib/ob3.js#buildCredential())
// with the local issuer key (app/lib/issuer-key.js), through the pinned,
// network-free documentLoader (app/lib/document-loader.js), and builds/signs
// the single reserved BitstringStatusListCredential.
//
// @digitalbazaar/vc, @digitalbazaar/data-integrity and
// @digitalbazaar/eddsa-rdfc-2022-cryptosuite are ESM-only while this repo is
// CommonJS, so all three are loaded with memoized dynamic imports, the same
// pattern used in app/lib/issuer-key.js.
//
// Real API shapes used here (verified against node_modules, not assumed):
//   - `@digitalbazaar/data-integrity` exports `DataIntegrityProof` (named).
//   - `@digitalbazaar/eddsa-rdfc-2022-cryptosuite` exports `cryptosuite`
//     (named) — an object ({canonize, createVerifier, name,
//     requiredAlgorithm}), not a class/constructor.
//   - `new DataIntegrityProof({signer, cryptosuite})` derives
//     `suite.verificationMethod` from `signer.id`/`signer.algorithm`
//     internally (see DataIntegrityProof.js's `_processSignatureParams`) —
//     we never set it ourselves.
//   - `@digitalbazaar/vc` exports `issue({credential, suite,
//     documentLoader})` and `verifyCredential({credential, suite,
//     documentLoader, checkStatus})`.
//
// KNOWN SHAPE FIX (found by an actual issue()/verifyCredential() round trip
// against the real libs, not by inspection alone): eddsa-rdfc-2022's own
// canonize.js hard-codes `safe: true` on every jsonld canonicalization call
// (node_modules/@digitalbazaar/eddsa-rdfc-2022-cryptosuite/lib/canonize.js).
// That makes ANY relative-IRI `@type` reference a hard error, not just a
// warning. app/lib/ob3.js's `credentialSchema[0].type` is the literal string
// `1EdTechJsonSchemaValidator2019` per the spec's own example (badgekit-stack
// docs/ob3-migration-spec.md §5.1) — but neither vendored context
// (vendor/ob3/credentials-v2.jsonld, vendor/ob3/ob-context-3.0.3.jsonld)
// defines that term (confirmed identical against a fresh, one-time fetch of
// the live https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json — this
// is a real gap in the upstream context, not a vendoring mistake), so it
// expands as a relative reference and eddsa-rdfc-2022's safe-mode
// canonicalization throws `jsonld.ValidationError` ("Relative @type
// reference found.") straight out of `vc.issue()`.
//
// Fix applied HERE, not in app/lib/ob3.js and not in the documentLoader: a
// locally-SCOPED JSON-LD context (an inline `@context` object, not a URL) is
// added only to the affected `credentialSchema` entry, only in the credential
// that actually gets signed. This resolves entirely from the entry's own
// literal content during jsonld expansion — the documentLoader is never even
// consulted for it — so the network-freedom invariant is untouched, and
// app/lib/ob3.js's top-level `@context` (asserted exactly equal to the
// two-element ordered pair by test/ob3-builder.test.js) is untouched too.
// The unsigned credential objects app/lib/ob3.js produces and asserts on are
// never mutated in place — signCredential() works on a deep clone.

const zlib = require('zlib')
const issuerKey = require('./issuer-key')
const makeDocumentLoader = require('./document-loader')

let vcPromise = null
function loadVc () {
  if (!vcPromise) {
    vcPromise = import('@digitalbazaar/vc')
    vcPromise.catch(function () { vcPromise = null })
  }
  return vcPromise
}

let dataIntegrityPromise = null
function loadDataIntegrity () {
  if (!dataIntegrityPromise) {
    dataIntegrityPromise = import('@digitalbazaar/data-integrity')
    dataIntegrityPromise.catch(function () { dataIntegrityPromise = null })
  }
  return dataIntegrityPromise
}

let cryptosuitePromise = null
function loadCryptosuite () {
  if (!cryptosuitePromise) {
    cryptosuitePromise = import('@digitalbazaar/eddsa-rdfc-2022-cryptosuite')
    cryptosuitePromise.catch(function () { cryptosuitePromise = null })
  }
  return cryptosuitePromise
}

// See the header comment: `1EdTechJsonSchemaValidator2019` isn't a term in
// either vendored context, so eddsa-rdfc-2022's safe-mode canonicalization
// rejects it as a relative @type reference. This locally-scoped context
// (inline JSON-LD data, not a URL — never touches the documentLoader) gives
// it an unambiguous absolute IRI, resolved entirely from the document's own
// content.
const SCHEMA_VALIDATOR_TYPE = '1EdTechJsonSchemaValidator2019'
const SCHEMA_VALIDATOR_TYPE_CONTEXT = {
  '1EdTechJsonSchemaValidator2019':
    'https://purl.imsglobal.org/spec/ob/v3p0#1EdTechJsonSchemaValidator2019',
}

// Deep-clones the unsigned credential (so app/lib/ob3.js's return value is
// never mutated) and scopes SCHEMA_VALIDATOR_TYPE_CONTEXT onto any
// `credentialSchema` entry using the untermed 1EdTech type string.
//
// If such an entry already carries its own `@context` (not produced by
// app/lib/ob3.js today, but a future caller/shape could), we never silently
// skip fixing it — a silent skip would leave the exact safe-mode
// "relative @type reference" failure this function exists to prevent. We
// either MERGE our term into an existing plain-object context (as long as it
// doesn't already map that term to something else), or throw loudly so a
// real conflict surfaces at signing time instead of failing (or worse,
// silently producing an unverifiable-elsewhere document).
function prepareForSigning (unsignedCredential) {
  const credential = JSON.parse(JSON.stringify(unsignedCredential))
  const raw = credential.credentialSchema
  const schemas = Array.isArray(raw) ? raw : (raw ? [raw] : [])
  schemas.forEach(function (entry) {
    if (!entry || entry.type !== SCHEMA_VALIDATOR_TYPE) return

    const existing = entry['@context']
    if (!existing) {
      entry['@context'] = SCHEMA_VALIDATOR_TYPE_CONTEXT
      return
    }

    if (typeof existing !== 'object' || Array.isArray(existing)) {
      throw new Error(
        'ob3-signer#prepareForSigning: credentialSchema entry already has a ' +
        'non-object `@context` (' + JSON.stringify(existing) + ') — cannot ' +
        'merge the `' + SCHEMA_VALIDATOR_TYPE + '` scoped term into it.'
      )
    }

    const wanted = SCHEMA_VALIDATOR_TYPE_CONTEXT[SCHEMA_VALIDATOR_TYPE]
    const current = existing[SCHEMA_VALIDATOR_TYPE]
    if (current && current !== wanted) {
      throw new Error(
        'ob3-signer#prepareForSigning: credentialSchema entry\'s `@context` ' +
        'already maps `' + SCHEMA_VALIDATOR_TYPE + '` to `' + current + '`, ' +
        'which conflicts with `' + wanted + '`.'
      )
    }

    entry['@context'] = Object.assign({}, existing, SCHEMA_VALIDATOR_TYPE_CONTEXT)
  })
  return credential
}

function loadSigningDeps () {
  return Promise.all([
    loadVc(),
    loadDataIntegrity(),
    loadCryptosuite(),
    issuerKey.getKeyPair(),
  ])
}

// signCredential(unsigned) -> Promise<signed>
// Signs an unsigned OB 3.0 credential (or any credential-shaped object, used
// also for the status list credential) with a fresh eddsa-rdfc-2022
// DataIntegrityProof, through the pinned documentLoader.
function signCredential (unsignedCredential) {
  return loadSigningDeps().then(function (deps) {
    const vc = deps[0]
    const DataIntegrityProof = deps[1].DataIntegrityProof
    const cryptosuite = deps[2].cryptosuite
    const keyPair = deps[3]

    const suite = new DataIntegrityProof({
      signer: keyPair.signer(),
      cryptosuite: cryptosuite,
    })
    const documentLoader = makeDocumentLoader()
    const credential = prepareForSigning(unsignedCredential)

    return vc.issue({ credential: credential, suite: suite, documentLoader: documentLoader })
  })
}

// 131,072-bit (16 KiB decompressed) all-zero bitstring — the spec-minimum
// size for a Bitstring Status List — gzip-compressed then multibase
// (base64url, prefix 'u') encoded, per the Bitstring Status List spec's
// `encodedList` format.
const STATUS_LIST_BYTE_LENGTH = 16 * 1024

function buildEncodedList () {
  const bitstring = Buffer.alloc(STATUS_LIST_BYTE_LENGTH, 0)
  const compressed = zlib.gzipSync(bitstring)
  return 'u' + compressed.toString('base64url')
}

function toIso8601Now () {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
}

// Unsigned BitstringStatusListCredential. @context is credentials/v2 ONLY —
// every term this credential needs (BitstringStatusListCredential,
// BitstringStatusList, statusPurpose, encodedList) is defined there (see
// vendor/ob3/credentials-v2.jsonld); adding the OB 3.0 context here would be
// both unnecessary and contrary to global-constraints.md's fixed @context
// ordering for the OpenBadgeCredential itself (this document is not one).
function buildStatusListCredential (baseUrl) {
  const id = baseUrl + '/public/credentials/status/0'
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: id,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: issuerKey.getDid(),
    validFrom: toIso8601Now(),
    credentialSubject: {
      id: id + '#list',
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList: buildEncodedList(),
    },
  }
}

// getStatusListCredential(baseUrl) -> Promise<signed>
// Built and signed once per process PER baseUrl, then memoized — keyed by
// baseUrl (not a single slot) because the credential's own `id` and its
// `credentialSubject.id` are derived from baseUrl; a bare single-slot memo
// would silently keep serving a credential whose `id`/`statusListCredential`
// pairing (which strict verifiers check for equality — spec's Bitstring
// Status List retrieval algorithm) belongs to a stale baseUrl. In practice
// baseUrl is now always exactly `PUBLIC_BASE_URL` (see
// app/routes/badge-instances.js — required whenever signing is configured),
// so this Map holds at most one entry in real deployments; it stays
// baseUrl-keyed anyway so a misconfiguration can't wire up cross-baseUrl
// contamination silently, and so tests that vary baseUrl per spawn() get
// correctly independent, non-stale credentials.
const statusListCredentialPromises = new Map()
function getStatusListCredential (baseUrl) {
  if (!statusListCredentialPromises.has(baseUrl)) {
    const promise = signCredential(buildStatusListCredential(baseUrl))
    promise.catch(function () { statusListCredentialPromises.delete(baseUrl) })
    statusListCredentialPromises.set(baseUrl, promise)
  }
  return statusListCredentialPromises.get(baseUrl)
}

module.exports = {
  signCredential: signCredential,
  getStatusListCredential: getStatusListCredential,
}
