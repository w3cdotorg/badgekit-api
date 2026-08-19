// A pinned JSON-LD documentLoader for @digitalbazaar/vc (Task 7). It NEVER
// touches the network: every context it can resolve is vendored on disk
// under vendor/ob3/ (see vendor/ob3/README.md), and the local issuer
// identity (the did document + its verificationMethod) is resolved via
// app/lib/issuer-key.js. Any other URL is rejected.
//
// Contract (what @digitalbazaar/vc / jsonld-signatures expect from a
// documentLoader): `async loader(url) -> {documentUrl, document, contextUrl}`
// — see node_modules/jsonld-signatures/lib/documentLoader.js#extendContextLoader.
//
// Verified empirically against a real @digitalbazaar/vc issue()/
// verifyCredential() round trip (task-6-report.md) that:
//
//   - The DID/security contexts (https://www.w3.org/ns/did/v1,
//     https://w3id.org/security/multikey/v1) referenced by the did
//     document's own `@context` are NEVER requested by that flow — the did
//     document and the verificationMethod object are consumed directly by
//     @digitalbazaar/data-integrity and @digitalbazaar/ed25519-multikey,
//     with no jsonld expansion of their own `@context`. They are
//     intentionally NOT vendored here.
//
//   - `ISSUER_DID#key-0` (the verificationMethod URL dereferenced during
//     proof verification, see DataIntegrityProof#getVerificationMethod)
//     must resolve to the verificationMethod object itself (the individual
//     Multikey), NOT the full did document. @digitalbazaar/ed25519-multikey's
//     from() (used by eddsa-rdfc-2022-cryptosuite's createVerifier())
//     requires a top-level `publicKeyMultibase`, which only the
//     verificationMethod object has — resolving to the full did document
//     there fails verification with "publicKeyMultibase property is
//     required".
//
//   - The bare `ISSUER_DID` IS requested too (separately from #key-0),
//     because AssertionProofPurpose validates that the verificationMethod
//     is listed in the controller document's `assertionMethod`.

const fs = require('fs')
const path = require('path')
const issuerKey = require('./issuer-key')

const CREDENTIALS_V2_URL = 'https://www.w3.org/ns/credentials/v2'
const OB_CONTEXT_URL = 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'

const VENDOR_DIR = path.join(__dirname, '..', '..', 'vendor', 'ob3')

// Loaded once and cached — these files never change at runtime.
const VENDORED_CONTEXTS = {}
VENDORED_CONTEXTS[CREDENTIALS_V2_URL] = readVendoredJson('credentials-v2.jsonld')
VENDORED_CONTEXTS[OB_CONTEXT_URL] = readVendoredJson('ob-context-3.0.3.jsonld')

function readVendoredJson (filename) {
  const raw = fs.readFileSync(path.join(VENDOR_DIR, filename), 'utf8')
  return JSON.parse(raw)
}

function makeDocumentLoader () {
  return function loader (url) {
    if (Object.prototype.hasOwnProperty.call(VENDORED_CONTEXTS, url)) {
      return Promise.resolve({
        documentUrl: url,
        document: VENDORED_CONTEXTS[url],
        contextUrl: null,
      })
    }

    const did = issuerKey.getDid()
    if (did && url === did) {
      return issuerKey.getDidDocument().then(function (didDocument) {
        return { documentUrl: url, document: didDocument, contextUrl: null }
      })
    }
    if (did && url === did + '#key-0') {
      return issuerKey.getDidDocument().then(function (didDocument) {
        const verificationMethod = findVerificationMethod(didDocument, url)
        if (!verificationMethod) {
          throw new Error('pinned loader: verificationMethod not found for ' + url)
        }
        return { documentUrl: url, document: verificationMethod, contextUrl: null }
      })
    }

    return Promise.reject(
      new Error('pinned loader: refusing network fetch of ' + url)
    )
  }
}

function findVerificationMethod (didDocument, id) {
  const methods = didDocument.verificationMethod || []
  for (let i = 0; i < methods.length; i++) {
    if (methods[i].id === id) return methods[i]
  }
  return null
}

module.exports = makeDocumentLoader
