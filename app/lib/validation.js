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
  isUrl: function (value) {
    return validatorContext.isURL(value, {require_tld: false});
  },
  is: function (value, pattern) {
    return validatorContext.matches(value, pattern);
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
