'use strict';

const Fs = require('fs');
const Manta = require('manta');
const ClientEncryption = require('.');

const client = Manta.createClient({
    sign: Manta.privateKeySigner({
        key: Fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8'),
        keyId: process.env.MANTA_KEY_ID,
        user: process.env.MANTA_USER
    }),
    user: process.env.MANTA_USER,
    url: process.env.MANTA_URL
});


const file = Fs.createReadStream(__dirname + '/README.md');
const path = '~~/stor/enc';
const key = 'FFFFFFFBD96783C6C91E2222';   // 24 bytes
const headers = {
  'm-encrypt-metadata': 'my secret message',
  'm-encrypt-metadata-cipher': 'aes/192/cbc'
};

const getKey = function (keyId, callback) {
  return callback(null, key);
};


ClientEncryption.put(path, file, { client, key, keyId: 'dev/test', cipher: 'aes/192/cbc', headers }, (err) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }

  ClientEncryption.get(path, { client, getKey }, (err, stream, res) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }

    console.log(res.headers);
    stream.pipe(process.stdout);
    setImmediate(() => {
      process.stdout.write('\n');
    });
  });
});
