# karmia-utility-crypto
Karmia utility crypto module

## Usage
```JavaScript
const karmia_utility_crypto = require('karmia-utility-crypto').default,
    kcrypto = new karmia_utility_crypto();
```

### hash

#### hash(algorithm, buffer, encoding)
- algorithm ```<string>```
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.hash('md5', Buffer.from('text'), 'binary');
```

#### sha1(buffer, encoding)
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.sha1(Buffer.from('text'), 'binary');
```

#### sha256(buffer, encoding)
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.sha256(Buffer.from('text'), 'binary');
```

#### sha512(buffer, encoding)
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.sha512(Buffer.from('text'), 'binary');
```

### stretching(algorithm, buffer, count, encoding)
- algorithm ```<string>```
- buffer ```<Buffer>```
- count ```<Number>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.stretching('sha256', Buffer.from('text'), 10000, 'binary');
```

### hmac

#### hmac(algorithm, secret, buffer, encoding)
- algorithm ```<string>```
- password ```<Buffer>```
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.hmac('md5', 'secret', Buffer.from('text'), 'binary');
```

#### hmac_sha1(secret, buffer, encoding)
- password ```<Buffer>```
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.hmac_sha1('secret', Buffer.from('text'), 'binary');
```

#### hmac_sha256(secret, buffer, encoding)
- password ```<Buffer>```
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.hmac_sha256('secret', Buffer.from('text'), 'binary');
```

#### hmac_sha512(secret, buffer, encoding)
- password ```<Buffer>```
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
kcrypto.hmac_sha512('secret', Buffer.from('text'), 'binary');
```


### encrypt

#### iv()
```JavaScript
const iv = kcrypto.iv();
```

#### encrypt(algorithm, password, buffer, encoding)
- algorithm ```<string>```
- password ```<Buffer>```
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
const password = Buffer.from('password'),
      data = Buffer.from('text');
kcrypto.encrypt('aes-256-ctr', password, data, 'binary');
```

#### decrypt(algorithm, password, data, encoding)
- algorithm ```<string>```
- password ```<Buffer>```
- data ```<Object>``` {data: encrypted}
- encoding ```<string>``` Output encoding

```JavaScript
const password = Buffer.from('password'),
      data = {data: 'encrypted'};
kcrypto.decrypt('aes-256-ctr', password, data, 'binary');
```

#### encryptiv(algorythm, password, iv, data, encoding)
- algorithm ```<string>```
- password ```<Buffer>```
- iv ```<Buffer>```
- buffer ```<Buffer>```
- encoding ```<string>``` Input encoding

```JavaScript
const password = Buffer.from('password'),
      iv = Buffer.from('iv'),
      buffer = Buffer.from('text');
kcrypto.encryptiv('aes-256-gcm', password, iv, data, 'binary');
```

#### decryptiv(algorithm, password, iv, data, encoding, tag_encoding)
- algorithm ```<string>```
- password ```<Buffer>```
- iv ```<Buffer>```
- data ```<Object>``` {data: encrypted} or {data: encrypted, tag: auth_tag}
- encoding ```<string>``` Output encoding
- tag_encoding ```<string>``` Auth tag input encoding

```JavaScript
const password = Buffer.from('password'),
    iv = Buffer.from('iv'),
    data = {
        data: 'encrypted',
        tag: 'auth_tag'
    };
kcrypto.decryptiv(algorithm, password, iv, data, 'binary', 'binary');
```
