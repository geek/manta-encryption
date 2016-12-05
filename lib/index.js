'use strict';

const Assert = require('assert');
const Crypto = require('crypto');
const Stream = require('stream');
const B64 = require('b64');


const internals = {};

/*
  Header Keys:
  m-encrypt-key-id
  m-encrypt-iv
  m-encrypt-mac
  m-encrypt-cipher
  m-encrypt-original-content-length
  m-encrypt-metadata
  m-encrypt-metadata-iv
  m-encrypt-metadata-mac
  m-encrypt-metadata-cipher
*/

exports.get = function (path, options, callback) {
  Assert(typeof options === 'object' && options && typeof callback === 'function', 'options and callback are required');
  Assert(options.client, 'manta client required');
  Assert(path, 'path of file is required');
  Assert(typeof options.getKey === 'function', 'getKey function required: (keyId, cb)');

  const manta = options.client;

  manta.info(path, (err, info) => {
    if (err) {
      return callback(err);
    }

    const invalidHeaders = internals.validateHeaders(info.headers);
    if (invalidHeaders) {
      return callback(new Error(`Headers are missing or invalid: ${invalidHeaders}`));
    }

    manta.get(path, (err, stream) => {
      if (err) {
        return callback(err);
      }

      // Not encrypted, return original file stream
      if (!info.headers['m-encrypt-key-id']) {
        return callback(null, stream);
      }

      options.getKey(info.headers['m-encrypt-key-id'], (err, key) => {
        if (err) {
          return callback(err);
        }

        const algorithm = internals.getAlgorithm(info.headers['m-encrypt-cipher']);
        const decipher = Crypto.createDecipheriv(algorithm, key, B64.decode(new Buffer(info.headers['m-encrypt-iv'])));
        const hmac = Crypto.createHmac('sha256', key);

        return callback(null, stream.pipe(decipher));

        /*
        stream.pipe(hmac);
        const digest = hmac.digest();
        if (digest.toString() !== B64.decode(info.headers['m-encrypt-mac'])) {
          return callback(new Error(`cipher hmac doesn't match stored m-encrypt-mac value`));
        }

        return callback(null, stream.pipe(decipher));
        */
      });
    });
  });
};


exports.put = function (path, input, options, callback) {
  Assert(options.client, 'manta client required');
  Assert(options.key, 'key is required');
  Assert(options.keyId, 'keyId is required');
  Assert(path, 'path to save file is required');
  Assert(options.cipher, 'cipher is required (cipher/width/mode)');
  Assert(input instanceof Stream.Readable, 'input stream is required');

  const manta = options.client;
  const iv = Crypto.randomBytes(16);
  const algorithm = internals.getAlgorithm(options.cipher);

  const cipher = Crypto.createCipheriv(algorithm, options.key, iv);
  const hmac = Crypto.createHmac('sha256', options.key);

  input.pipe(cipher); //.pipe(hmac);

  const headers = {
    'm-encrypt-key-id': options.keyId,
    'm-encrypt-iv': B64.encode(iv),
    'm-encrypt-cipher': options.cipher,
    //'m-encrypt-mac': B64.encode(hmac.digest())
  };

  manta.put(path, cipher, { headers }, callback);
};


internals.validateHeaders = function (headers) {
  // TODO: Check that all required headers exist
  return null;
};


internals.getAlgorithm = function (cipher) {
  const parts = cipher.split('/');
  return parts[0] + parts[1];
};