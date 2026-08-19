const validatorContext = require('validator')

function makeValidator (validation) {
  return function (row) {
    return this.fields.reduce(function (errors, field) {
      const value = row[field]
      try {
        const validator = validation[field] || noop;
        validator.call(validatorContext, value);
      }
      catch(e) {
        e.field = field;
        e.value = value || ''
        delete e.name
        errors.push(e);
      }
      return errors;
    }, []);
  };
};

function noop() {}

function required () {
  var fn = confirmValidatorFunction.apply(null, arguments);

  return function (value) {
    if (typeof value === 'undefined' || value === null)
      throw new Error('Required field');

    return fn.call(this, value);
  }
}

function optional () {
  var fn = confirmValidatorFunction.apply(null, arguments);

  return function (value) {
    if (typeof value === 'undefined' || value === null)
      return;

    return fn.call(this, value);
  }
}

// validator >= 3 dropped the chainable `check()` API and renamed some
// validators; map the legacy names used by the models onto the modern API
const legacyValidators = {
  len: function (value, min, max) {
    return validatorContext.isLength(value, {min: min, max: max});
  },
  // validator@2 (what this app was built against) made the scheme
  // OPTIONAL (`(?:(?:https?|ftp):\/\/)?`) but REQUIRED a TLD, so
  // "http://localhost" passed only because "localhost" was special-cased,
  // not because a bare hostname was ever acceptable in general - a value
  // like "ridiculous-url" was always invalid under the old contract.
  // validator@13 flips both defaults: require_protocol defaults to false
  // and require_tld defaults to true, which would reject "localhost"
  // hosts used elsewhere in this app. We deliberately choose
  // require_tld:false (to keep local/host-only URLs valid, matching the
  // old localhost carve-out) plus require_protocol:true (to keep bare
  // hostnames like "ridiculous-url" invalid, matching the old default).
  // This is a considered re-derivation of the old contract, not a
  // mechanical restoration of validator@2's own option set.
  isUrl: function (value) {
    return validatorContext.isURL(value, {require_tld: false, require_protocol: true});
  },
  is: function (value, pattern) {
    return validatorContext.matches(value, pattern);
  },
  // validator >= 7 tightened isDate() to ISO-ish formats by default, but this
  // API has always accepted whatever `Date.parse` understands (e.g.
  // "March 9, 1979 12:00:00"), matching the pre-3.0 `validator` behavior this
  // app was built against. Keep that looser contract instead of silently
  // rejecting previously-valid application/badge-instance payloads.
  isDate: function (value) {
    return !isNaN(Date.parse(value));
  },
}

function confirmValidatorFunction (fn) {
  if (typeof fn === 'function')
    return fn;

  var validator = '' + fn;
  var args = Array.prototype.slice.call(arguments, 1);

  return function (value) {
    var checker = legacyValidators[validator] || validatorContext[validator];
    if (typeof checker !== 'function')
      throw new Error('Unknown validator: ' + validator);
    if (!checker.apply(null, [String(value)].concat(args)))
      throw new Error('Invalid value for `' + validator + '`');
  }
}

exports = module.exports = {
  makeValidator: makeValidator,
  required: required,
  optional: optional
}
