## Manta Client Encryption

### API

#### `put(path, stream, { client, key, keyId, cipher }, callback)`

- `path`: path to save file to in Manta
- `stream`: file to put to Manta
- `client`: Manta client instance
- `key`: private key to use for encryption
- `keyId`: ID for key, will be saved with file metadata
- `cipher`: encryption cipher to use in the form alg/width/mode (e.g. `aes/192/cbc`)

The `callback` has the signature `(err, stream, res)`


#### `get(path, { client, getKey }, callback)`

- `path`: Manta path to file to download
- `client`: Manta client instance
- `getKey`: function that takes a `keyId` and returns in the callback the key. The callback has the form `(err, key)`

The `callback` has the signature `(err, stream, res)`


### Security Checks

1. The encrypted file has an HMAC generated for it using sha256 to detect tampering
1. The unencrypted file is hashed as well as the byte length to detect tampering


### Security Considerations

1. Do not store the private key in the same place/datacenter as you are storing the encrypted files


See example.js for usage examples.
