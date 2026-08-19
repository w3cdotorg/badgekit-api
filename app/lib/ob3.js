// Pure builder: BadgeKit instance/badge/issuer data --> an UNSIGNED Open
// Badges 3.0 `OpenBadgeCredential` (no `proof`). No DB access, no network
// calls, no env reads — every value it needs comes in through parameters.
// Signing and DB/route wiring happen elsewhere (later tasks); this module
// only maps already-assembled objects, following
// badgekit-stack/docs/ob3-migration-spec.md §5.1 (mapping table + example).
//
// Expected shapes of buildCredential({instance, badge, issuerOrg, baseUrl,
// issuerDid}) — all plain objects, already loaded/resolved by the caller:
//
//   instance   — a badgeInstances row (see app/models/badge-instance.js):
//     .id       {Number}             auto-increment PK
//                                     -> credentialStatus.statusListIndex / id fragment
//     .slug     {String}             -> credential `id` (baseUrl + /public/credentials/:slug)
//     .email    {String}             raw recipient email, hashed here with .salt
//     .salt     {String}             per-instance hex salt (badge-instance.js#formatUserInput)
//     .issuedOn {Date|Number}        a Date, or unix seconds -> validFrom / awardedDate
//     .expires  {Date|Number|falsy}  same shape as issuedOn, optional -> validUntil
//
//   badge      — the shape assembled from makeBadgeClass()/Badge.getOne() in
//                app/routes/badge-instances.js, PLUS the badge's own already-
//                resolved absolute public BadgeClass URL (what
//                req.resolvePath(makeBadgeClassUrl(badge)) produces today for
//                makeAssertion()'s `badge` field):
//     .name                {String}
//     .consumerDescription {String}                        -> achievement.description
//     .url                 {String}                        absolute public BadgeClass URL
//                                                            -> achievement.id
//     .criteriaUrl         {String}                         absolute URL -> achievement.criteria.id
//     .criteria            {Array<{description}>}           optional, rows as returned by
//                                                            app/models/criteria.js#toResponse
//                                                            -> achievement.criteria.narrative
//                                                            (descriptions joined; omitted if empty)
//     .alignments          {Array<{name,url,description}>}  optional, rows as returned by
//                                                            app/models/alignment.js#toResponse
//                                                            -> achievement.alignment[]
//     .imageUrl            {String}                         absolute URL -> achievement.image.id
//
//   issuerOrg  — the result of the existing makeIssuerOrganization() cascade
//                (program > issuer > system), in badge-instances.js:
//     .name  {String}
//     .url   {String}
//     .email {String}  optional
//
//   baseUrl    {String} absolute origin of the API, no trailing slash, e.g.
//              "http://localhost:8080" — used to build the credential `id`
//              and the credentialStatus URLs.
//
//   issuerDid  {String} e.g. "did:web:localhost%3A8080" -> issuer.id
//
// Returns a plain object: the credential, UNSIGNED (no `proof` property).
// A later task signs it (Data Integrity, eddsa-rdfc-2022) and persists it.

const crypto = require('crypto')
const unixtimeFromDate = require('./unixtime-from-date')

// @context order is fixed by the spec (global-constraints.md): VC Data
// Model 2.0 context first, then the OB 3.0 context.
const CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',
]

const OFFICIAL_SCHEMA_URL =
  'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json'

function buildCredential (params) {
  const instance = params.instance
  const badge = params.badge
  const issuerOrg = params.issuerOrg
  const baseUrl = params.baseUrl
  const issuerDid = params.issuerDid

  const validFrom = toIso8601(instance.issuedOn)

  const issuer = {
    id: issuerDid,
    type: ['Profile'],
    name: issuerOrg.name,
    url: issuerOrg.url,
  }
  if (issuerOrg.email) issuer.email = issuerOrg.email

  const achievement = {
    id: badge.url,
    type: ['Achievement'],
    name: badge.name,
    description: badge.consumerDescription,
    criteria: makeCriteria(badge),
    alignment: makeAlignments(badge),
  }
  if (badge.imageUrl) achievement.image = { id: badge.imageUrl, type: 'Image' }

  const credential = {
    '@context': CONTEXT.slice(),
    id: baseUrl + '/public/credentials/' + instance.slug,
    type: ['VerifiableCredential', 'OpenBadgeCredential'],
    name: badge.name,
    issuer: issuer,
    validFrom: validFrom,
    awardedDate: validFrom,
    credentialSubject: {
      type: ['AchievementSubject'],
      identifier: [{
        type: 'IdentityObject',
        hashed: true,
        identityHash: identityHash(instance.email, instance.salt),
        identityType: 'emailAddress',
        salt: instance.salt,
      }],
      achievement: achievement,
    },
    credentialStatus: {
      id: baseUrl + '/public/credentials/status/0#' + instance.id,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(instance.id),
      statusListCredential: baseUrl + '/public/credentials/status/0',
    },
    credentialSchema: [{
      id: OFFICIAL_SCHEMA_URL,
      type: '1EdTechJsonSchemaValidator2019',
    }],
  }

  if (instance.expires) credential.validUntil = toIso8601(instance.expires)

  return credential
}

function identityHash (email, salt) {
  return 'sha256$' + crypto.createHash('sha256').update(email + salt).digest('hex')
}

function makeCriteria (badge) {
  const criteria = { id: badge.criteriaUrl }
  const narrative = (badge.criteria || [])
    .map(function (row) { return row.description })
    .filter(Boolean)
    .join('\n\n')
  if (narrative) criteria.narrative = narrative
  return criteria
}

function makeAlignments (badge) {
  return (badge.alignments || []).map(function (alignment) {
    return {
      type: ['Alignment'],
      targetName: alignment.name,
      targetUrl: alignment.url,
      targetDescription: alignment.description,
    }
  })
}

// Normalizes a Date instance or a unix timestamp (seconds or milliseconds —
// see unixtime-from-date.js) to an ISO 8601 UTC string at second precision
// with a literal "Z" suffix, e.g. "2026-08-19T14:29:21Z".
function toIso8601 (dateOrUnixtime) {
  const seconds = unixtimeFromDate(dateOrUnixtime)
  return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
}

module.exports = {
  buildCredential: buildCredential,
}
