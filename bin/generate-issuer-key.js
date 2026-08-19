#!/usr/bin/env node
// Generates an Ed25519/Multikey key pair for OB 3.0 issuance.
//
// Usage: node bin/generate-issuer-key.js [did]
//   (default did: did:web:localhost%3A8080 — test domain only, see
//   global-constraints.md; use a disposable tunnel hostname for external
//   validation, never a "real" domain.)
//
// Prints the ISSUER_DID / ISSUER_SIGNING_KEY exports to set in the
// environment (never commit them, never store them in the DB or image) and
// the resulting did.json for reference.
//
// @digitalbazaar/ed25519-multikey is ESM-only; this script uses a dynamic
// import since the repo is CommonJS.

var did = process.argv[2] || 'did:web:localhost%3A8080'

import('@digitalbazaar/ed25519-multikey').then(function (multikey) {
  return multikey.generate({ id: did + '#key-0', controller: did })
}).then(function (keyPair) {
  // canonicalize: true → the exported secretKeyMultibase is the canonical
  // 32-byte-seed form (not the legacy seed+publicKey concatenation). This is
  // the form app/lib/issuer-key.js expects in ISSUER_SIGNING_KEY.
  return keyPair.export({ publicKey: true, secretKey: true, canonicalize: true })
}).then(function (exported) {
  console.log('# Add to your environment (NEVER commit this):')
  console.log('export ISSUER_DID=' + JSON.stringify(did))
  console.log('export ISSUER_SIGNING_KEY=' + JSON.stringify(exported.secretKeyMultibase))
  console.log('')
  console.log('# did.json (served at /.well-known/did.json once signing is configured):')
  console.log(JSON.stringify({
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1',
    ],
    id: did,
    verificationMethod: [{
      id: did + '#key-0',
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: exported.publicKeyMultibase,
    }],
    assertionMethod: [did + '#key-0'],
  }, null, 2))
}).catch(function (err) {
  console.error(err)
  process.exit(1)
})
