const Promise = require('bluebird');
const log = require('../lib/logger');
const db = require('../lib/db');
const sha256 = require('../lib/hash').sha256;
const jws = require('jws');

const Webhooks = db.table('webhooks', {
  fields: [
    'id',
    'url',
    'secret',
    'systemId',
  ],
  relationships: {
    system: {
      type: 'hasOne',
      local: 'systemId',
      foreign: { table: 'systems', key: 'id' },
      optional: false,
    },
  },
  methods: {
    call: function (hookData, callback) {
      const hookDataString = JSON.stringify(hookData);
      const hookDataHash = sha256(hookDataString);
      const token = jws.sign({
        secret: this.secret,
        header: {typ: 'JWT', alg: 'HS256'},
        payload: {
          body: {
            alg: 'sha256',
            hash: hookDataHash,
          },
        },
      });
      const headers = {
        'Content-Type': 'application/json',
        'Authorization': 'JWT token="'+token+'"',
      };

      return new Promise(function (resolve, reject) {
        fetch(this.url, {
          method: 'POST',
          headers: headers,
          body: hookDataString,
        }).then(function (fetchRes) {
          return fetchRes.text().then(function (body) {
            // Preserve the shape callers expect from the old `request`
            // library, where `res.statusCode` is read directly.
            const res = {
              statusCode: fetchRes.status,
              headers: fetchRes.headers,
              ok: fetchRes.ok,
            };

            if (callback)
              return callback(null, res, body);

            return resolve({ res: res, body: body });
          });
        }).catch(function (err) {
          if (callback)
            return callback(err);

          return reject(err);
        });
      }.bind(this))
    }
  }
});

exports = module.exports = Webhooks;
