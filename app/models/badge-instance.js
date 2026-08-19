const crypto = require('crypto')
const dateFromUnixtime = require('../lib/date-from-unixtime')
const db = require('../lib/db');
const validation = require('../lib/validation')
const sha1 = require('../lib/hash').sha1

const makeValidator = validation.makeValidator;
const optional = validation.optional;
const required = validation.required;

const BadgeInstances = db.table('badgeInstances', {
  fields: [
    'id',
    'slug',
    'email',
    'issuedOn',
    'expires',
    'claimCode',
    'badgeId',
    'salt',
    'credential',
  ],
  relationships: {
    badge: {
      type: 'hasOne',
      local: 'badgeId',
      foreign: { table: 'badges', key: 'id' },
      optional: false
    },
  },
})

BadgeInstances.formatUserInput = function formatUserInput(obj) {
  return {
    slug: obj.slug || sha1(Date.now() + JSON.stringify(obj)),
    email: obj.email,
    issuedOn: obj.issuedOn || dateFromUnixtime(Date.now()),
    expires: obj.expires ? dateFromUnixtime(obj.expires) : null,
    claimCode: obj.claimCode,
    salt: obj.salt || crypto.randomBytes(8).toString('hex'),
  }
}

BadgeInstances.toResponse = function toResponse(row, req) {
  const relativeAssertionUrl = '/public/assertions/' + row.slug;
  const assertionUrl = req.resolvePath(relativeAssertionUrl);
  // OB 3.0 (Task 7): additive, next to assertionUrl — the 1.x assertion
  // stays the `Location`/primary artifact, this just points at the signed
  // OpenBadgeCredential (lazily signed on first GET, see
  // app/routes/badge-instances.js).
  const relativeCredentialUrl = '/public/credentials/' + row.slug;
  const credentialUrl = req.resolvePath(relativeCredentialUrl);

  return {
    slug: row.slug,
    email: row.email,
    expires: row.expires,
    issuedOn: row.issuedOn,
    claimCode: row.claimCode,
    assertionUrl: assertionUrl,
    credentialUrl: credentialUrl,
    badge: row.badge ? row.badge.toResponse(req) : null
  }
};

BadgeInstances.validateRow = makeValidator({
  id: optional('isInt'),
  email: required('isEmail'),
  claimCode: optional('len', 0, 255),
  badgeId: required('isInt'),
})

exports = module.exports = BadgeInstances
