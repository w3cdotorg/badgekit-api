// Tests for app/lib/ob3.js — the pure BadgeKit instance -> OB 3.0
// OpenBadgeCredential builder.
//
// Pure unit test: no DB, no network, no spawn(app) — everything is an
// in-memory fixture. Focused run:
//   NODE_ENV=test npx tap --no-coverage test/ob3-builder.test.js
//
// Fixture values (slug, email, salt, identityHash, issuedOn epoch ->
// validFrom) are the REAL captured values from
// badgekit-stack/docs/ob3-migration-spec.md §2.2/§5.1 — if this test
// disagrees with app/lib/ob3.js, the implementation is wrong, not the test.
const test = require('tap').test
const Ajv2019 = require('ajv/dist/2019')
const addFormats = require('ajv-formats')
const schema = require('../vendor/ob3/ob_v3p0_achievementcredential_schema.json')
const ob3 = require('../app/lib/ob3')

const ajv = new Ajv2019({ strict: false })
addFormats(ajv)
const validate = ajv.compile(schema)

const BASE_URL = 'http://localhost:8080'
const ISSUER_DID = 'did:web:localhost%3A8080'

// Spec §5.1 example badge/issuer, with the badge's already-resolved absolute
// public BadgeClass URL attached as `.url` (see the header comment in
// app/lib/ob3.js for why that field is expected on `badge`).
function baseBadge () {
  return {
    name: 'OB3 Spec Demo Badge',
    consumerDescription: 'Demonstrates contribution to the Open Badges 3.0 migration effort.',
    url: BASE_URL + '/public/systems/wooclap/badges/ob3-spec-demo',
    criteriaUrl: BASE_URL + '/criteria/ob3-spec-demo',
    criteria: [],
    alignments: [],
    imageUrl: BASE_URL + '/images/ob3-demo.png',
  }
}

function baseIssuerOrg () {
  return {
    name: 'Wooclap System',
    url: BASE_URL,
  }
}

// Spec §2.2/§5.1: instance decerned to alice@example.org, salt
// a9f2c4a17d0b4e6c, issuedOn epoch 1787149761 (-> 2026-08-19T14:29:21Z).
function baseInstance () {
  return {
    id: 1,
    slug: 'b91ca0db5d9a4c0cb19b11c85da6645aa6c62bf3',
    email: 'alice@example.org',
    salt: 'a9f2c4a17d0b4e6c',
    issuedOn: 1787149761,
    expires: null,
  }
}

function build (overrides) {
  overrides = overrides || {}
  return ob3.buildCredential({
    instance: overrides.instance || baseInstance(),
    badge: overrides.badge || baseBadge(),
    issuerOrg: overrides.issuerOrg || baseIssuerOrg(),
    baseUrl: overrides.baseUrl || BASE_URL,
    issuerDid: overrides.issuerDid || ISSUER_DID,
  })
}

test('ob3.buildCredential: @context is the exact ordered pair required by the spec', function (t) {
  const credential = build()
  t.same(credential['@context'], [
    'https://www.w3.org/ns/credentials/v2',
    'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',
  ])
  t.end()
})

test('ob3.buildCredential: type is [VerifiableCredential, OpenBadgeCredential]', function (t) {
  const credential = build()
  t.same(credential.type, ['VerifiableCredential', 'OpenBadgeCredential'])
  t.end()
})

test('ob3.buildCredential: validFrom/awardedDate are ISO 8601 UTC, second precision, from the epoch', function (t) {
  const credential = build()
  t.equal(credential.validFrom, '2026-08-19T14:29:21Z')
  t.equal(credential.awardedDate, '2026-08-19T14:29:21Z')
  t.end()
})

test('ob3.buildCredential: validUntil is present only when instance.expires is set', function (t) {
  const withoutExpiry = build()
  t.notOk('validUntil' in withoutExpiry, 'no validUntil when instance.expires is falsy')

  const instance = baseInstance()
  instance.expires = 1818685761 // 2027-08-19T14:29:21Z
  const withExpiry = build({ instance: instance })
  t.equal(withExpiry.validUntil, '2027-08-19T14:29:21Z')
  t.end()
})

test('ob3.buildCredential: identityHash is sha256$hex(email + salt), exactly', function (t) {
  const credential = build()
  const identifier = credential.credentialSubject.identifier[0]
  t.equal(identifier.identityHash,
    'sha256$03fa3c990a282b068f5c58c8fd44527052142d8acb69e36c7f9896623701bbbb')
  t.equal(identifier.type, 'IdentityObject')
  t.equal(identifier.hashed, true)
  t.equal(identifier.identityType, 'emailAddress')
  t.equal(identifier.salt, 'a9f2c4a17d0b4e6c')
  t.end()
})

test('ob3.buildCredential: credentialStatus.statusListIndex is String(instance.id) for a shard-0 id', function (t) {
  const instance = baseInstance()
  instance.id = 42
  const credential = build({ instance: instance })
  t.equal(credential.credentialStatus.statusListIndex, '42')
  t.equal(credential.credentialStatus.type, 'BitstringStatusListEntry')
  t.equal(credential.credentialStatus.statusPurpose, 'revocation')
  t.equal(credential.credentialStatus.id, BASE_URL + '/public/credentials/status/0#42')
  t.equal(credential.credentialStatus.statusListCredential, BASE_URL + '/public/credentials/status/0')
  t.end()
})

// F2 (final whole-plan review): the status list is fixed at 131,072 entries
// (global-constraints.md) — instance ids at or beyond that ceiling must
// shard into a new status list credential rather than sign an out-of-range
// bit index into an immutable credential. Shard math: shard = floor(id /
// 131072), index within that shard = id % 131072.
test('ob3.buildCredential: F2 — instance ids >= 131072 shard into a new status list (id 131073 -> shard 1, index "1")', function (t) {
  const instance = baseInstance()
  instance.id = 131073
  const credential = build({ instance: instance })
  t.equal(credential.credentialStatus.statusListIndex, '1', 'index wraps to id % 131072')
  t.equal(credential.credentialStatus.statusListCredential, BASE_URL + '/public/credentials/status/1',
    'statusListCredential points at shard 1')
  t.equal(credential.credentialStatus.id, BASE_URL + '/public/credentials/status/1#131073',
    'credentialStatus.id is built from the sharded statusListCredential URL')
  t.end()
})

test('ob3.buildCredential: F2 — the last id in shard 0 (131071) still resolves to shard 0', function (t) {
  const instance = baseInstance()
  instance.id = 131071
  const credential = build({ instance: instance })
  t.equal(credential.credentialStatus.statusListIndex, '131071')
  t.equal(credential.credentialStatus.statusListCredential, BASE_URL + '/public/credentials/status/0')
  t.end()
})

test('ob3.buildCredential: F2 — the first id in shard 1 (131072) resolves to shard 1, index 0', function (t) {
  const instance = baseInstance()
  instance.id = 131072
  const credential = build({ instance: instance })
  t.equal(credential.credentialStatus.statusListIndex, '0')
  t.equal(credential.credentialStatus.statusListCredential, BASE_URL + '/public/credentials/status/1')
  t.end()
})

test('ob3.buildCredential: credentialSchema references the vendored official schema', function (t) {
  const credential = build()
  t.same(credential.credentialSchema, [{
    id: 'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json',
    type: '1EdTechJsonSchemaValidator2019',
  }])
  t.end()
})

test('ob3.buildCredential: has no `proof` — the credential is unsigned', function (t) {
  const credential = build()
  t.notOk('proof' in credential, 'no proof property')
  t.end()
})

test('ob3.buildCredential: maps achievement / issuer / id fields per §5.1', function (t) {
  const credential = build()
  t.equal(credential.id, BASE_URL + '/public/credentials/b91ca0db5d9a4c0cb19b11c85da6645aa6c62bf3')
  t.equal(credential.name, 'OB3 Spec Demo Badge')
  t.same(credential.issuer, {
    id: ISSUER_DID,
    type: ['Profile'],
    name: 'Wooclap System',
    url: BASE_URL,
  })
  const achievement = credential.credentialSubject.achievement
  t.equal(achievement.id, BASE_URL + '/public/systems/wooclap/badges/ob3-spec-demo')
  t.same(achievement.type, ['Achievement'])
  t.equal(achievement.name, 'OB3 Spec Demo Badge')
  t.equal(achievement.description,
    'Demonstrates contribution to the Open Badges 3.0 migration effort.')
  t.same(achievement.criteria, { id: BASE_URL + '/criteria/ob3-spec-demo' })
  t.same(achievement.image, { id: BASE_URL + '/images/ob3-demo.png', type: 'Image' })
  t.same(achievement.alignment, [])
  t.end()
})

test('ob3.buildCredential: issuer.email is included only when issuerOrg has one', function (t) {
  const withoutEmail = build()
  t.notOk('email' in withoutEmail.issuer)

  const issuerOrg = baseIssuerOrg()
  issuerOrg.email = 'issuer@example.org'
  const withEmail = build({ issuerOrg: issuerOrg })
  t.equal(withEmail.issuer.email, 'issuer@example.org')
  t.end()
})

test('ob3.buildCredential: criteria narrative is joined from badge.criteria rows when present', function (t) {
  const badge = baseBadge()
  badge.criteria = [
    { description: 'Complete the workshop.' },
    { description: 'Submit the final project.' },
  ]
  const credential = build({ badge: badge })
  t.same(credential.credentialSubject.achievement.criteria, {
    id: BASE_URL + '/criteria/ob3-spec-demo',
    narrative: 'Complete the workshop.\n\nSubmit the final project.',
  })
  t.end()
})

test('ob3.buildCredential: alignments map to Alignment entries (targetName/targetUrl/targetDescription)', function (t) {
  const badge = baseBadge()
  badge.alignments = [
    { name: 'CASE Framework Item', url: 'https://example.org/case/1', description: 'Some standard.' },
  ]
  const credential = build({ badge: badge })
  t.same(credential.credentialSubject.achievement.alignment, [{
    type: ['Alignment'],
    targetName: 'CASE Framework Item',
    targetUrl: 'https://example.org/case/1',
    targetDescription: 'Some standard.',
  }])
  t.end()
})

test('ob3.buildCredential: validates against the vendored official OB 3.0 schema (base fixture)', function (t) {
  const credential = build()
  const valid = validate(credential)
  t.ok(valid, 'credential is schema-valid: ' + JSON.stringify(validate.errors))
  t.end()
})

test('ob3.buildCredential: validates against the vendored official OB 3.0 schema (with expires, criteria, alignments)', function (t) {
  const instance = baseInstance()
  instance.expires = 1818685761
  const badge = baseBadge()
  badge.criteria = [{ description: 'Complete the workshop.' }]
  badge.alignments = [
    { name: 'CASE Framework Item', url: 'https://example.org/case/1', description: 'Some standard.' },
  ]
  const credential = build({ instance: instance, badge: badge })
  const valid = validate(credential)
  t.ok(valid, 'credential is schema-valid: ' + JSON.stringify(validate.errors))
  t.end()
})
