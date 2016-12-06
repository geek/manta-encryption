'use strict';

const Assert = require('assert');
const Crypto = require('crypto');
const Stream = require('stream');
const B64 = require('b64');


const internals = {
  requiredHeaders: [
    'm-encrypt-key-id',
    'm-encrypt-iv',
    'm-encrypt-cipher',
    'm-encrypt-mac',
    'm-encrypt-original-content-length'
  ]
};

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

  manta.get(path, (err, stream, res) => {
    if (err) {
      return callback(err, null, res);
    }

    // Not encrypted, return original file stream
    if (res.headers['m-encrypt-support'] !== 'client') {
      return callback(null, stream, res);
    }

    const invalidHeaders = internals.validateHeaders(res.headers);
    if (invalidHeaders) {
      return callback(new Error(`Headers are missing or invalid: ${invalidHeaders}`), null, res);
    }

    options.getKey(res.headers['m-encrypt-key-id'], (err, key) => {
      if (err) {
        return callback(err, null, res);
      }

      const algorithm = internals.getAlgorithm(res.headers['m-encrypt-cipher']);
      const decipher = Crypto.createDecipheriv(algorithm, key, B64.decode(new Buffer(res.headers['m-encrypt-iv'])));
      const hmac = Crypto.createHmac('sha256', key);
      const output = new Stream.PassThrough();
      let byteLength = 0;

      stream.on('data', (data) => {
        hmac.update(data);
      });

      decipher.on('data', (data) => {
        byteLength += Buffer.byteLength(data);
      });

      decipher.once('end', () => {
        const digest = hmac.digest('base64');

        if (digest !== res.headers['m-encrypt-mac']) {
          return callback(new Error(`cipher hmac doesn't match stored m-encrypt-mac value`), null, res);
        }

        if (byteLength !== parseInt(res.headers['m-encrypt-original-content-length'])) {
          return callback(new Error(`decrypted file size doesn't match original copy`), null, res);
        }

        internals.decryptMetadata(res.headers, key, () => {
          callback(null, output, res);
        });
      });


      stream.pipe(decipher).pipe(output);
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
  const output = new Stream.PassThrough();
  let byteLength = 0;

  cipher.on('data', (data) => {
    hmac.update(data);
  });

  input.on('data', (data) => {
    byteLength += Buffer.byteLength(data);
  });

  cipher.once('end', (data) => {
    const headers = {
      'm-encrypt-support': 'client',
      'm-encrypt-key-id': options.keyId,
      'm-encrypt-iv': B64.encode(iv).toString(),
      'm-encrypt-cipher': options.cipher,
      'm-encrypt-mac': hmac.digest('base64'),
      'm-encrypt-original-content-length': byteLength
    };

    if (options.headers && options.headers['m-encrypt-metadata']) {
      return internals.encryptMetadata(headers, options.headers, iv, options.key, () => {
        manta.put(path, output, { headers }, callback);
      });
    }

    manta.put(path, output, { headers }, callback);
  });

  input.pipe(cipher).pipe(output);
};


internals.validateHeaders = function (headers) {
  const missingHeaders = internals.requiredHeaders.reduce((header) => {
    if (headers[header] === undefined || headers[header] === null) {
      return header;
    }
  }) || [];

  if (headers['m-encrypt-metadata'] !== undefined
    && headers['m-encrypt-metadata'] !== null
    && !headers['m-encrypt-metadata-cipher']) {

    missingHeaders.push('m-encrypt-metadata-cipher');
  }

  return missingHeaders.length ? missingHeaders : null;
};


internals.getAlgorithm = function (cipher) {
  const parts = cipher.split('/');
  return parts[0] + parts[1];
};


internals.encryptMetadata = function (reqHeaders, headers, iv, key, callback) {
  reqHeaders['m-encrypt-metadata-iv'] = B64.encode(iv).toString();
  reqHeaders['m-encrypt-metadata-cipher'] = headers['m-encrypt-metadata-cipher'];

  const algorithm = internals.getAlgorithm(headers['m-encrypt-metadata-cipher']);

  const cipher = Crypto.createCipheriv(algorithm, key, iv);
  const hmac = Crypto.createHmac('sha256', key);

  let bufs = []
  cipher.on('data', (data) => {
    bufs.push(data);
  });

  cipher.once('finish', () => {
    const encrypted = Buffer.concat(bufs);
    reqHeaders['m-encrypt-metadata'] = B64.encode(encrypted).toString();
    hmac.update(encrypted);
    reqHeaders['m-encrypt-metadata-mac'] = hmac.digest('base64');
    callback();
  });

  cipher.write(headers['m-encrypt-metadata']);
  cipher.end();
};


internals.decryptMetadata = function (headers, key, callback) {
  if (!headers['m-encrypt-metadata']) {
    return callback();
  }

  const algorithm = internals.getAlgorithm(headers['m-encrypt-metadata-cipher']);
  const decipher = Crypto.createDecipheriv(algorithm, key, B64.decode(new Buffer(headers['m-encrypt-metadata-iv'])));
  const hmac = Crypto.createHmac('sha256', key);

  let bufs = []
  decipher.on('data', (data) => {
    bufs.push(data);
  });

  decipher.once('finish', () => {
    hmac.update(B64.decode(new Buffer(headers['m-encrypt-metadata'])));
    headers['m-encrypt-metadata'] = Buffer.concat(bufs).toString();

    if (headers['m-encrypt-metadata-mac'] !== hmac.digest('base64')) {
      return callback(new Error(`mac hash doesn't match`));
    }

    callback();
  });

  decipher.write(B64.decode(new Buffer(headers['m-encrypt-metadata'])));
  decipher.end();
};
