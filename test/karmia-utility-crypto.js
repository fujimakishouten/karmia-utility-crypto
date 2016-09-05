/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/*jslint node: true, nomen: true */
/*global describe, it */
'use strict';


// Variables
const crypto = require('crypto'),
    expect = require('expect.js'),
    karamia_utility_random = require('../lib'),
    kcrypto = karamia_utility_random();


// Test
describe('karmia-utility-crypto', function () {
    describe('hash', function () {
        it('Should get MD5 hash', function () {
            const result = kcrypto.hash('md5', 'Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(32);
        });

        it('Should get SHA512/256 hash', function () {
            const result = kcrypto.hash('sha512/256', 'Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(64);
        });
    });

    describe('sha1', function () {
        it('Should get SHA1 hash', function () {
            const result = kcrypto.sha1('Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(40);
        });
    });

    describe('sha256', function () {
        it('Should get SHA256 hash', function () {
            const result = kcrypto.sha256('Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(64);
        });
    });

    describe('sha512', function () {
        it('Should get SHA512 hash', function () {
            const result = kcrypto.sha512('Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(128);
        });
    });

    describe('stretching', function () {
        it('Should stretching hash function', function () {
            const data = 'Hello, world.',
                sha512 = kcrypto.sha512(data),
                result = kcrypto.stretching('sha512', data, 10);

            expect(result).to.not.be(sha512);
        });
    });

    describe('hmac', function () {
        it('Should get MD5 HMAC digest', function () {
            const result = kcrypto.hmac('md5', 'secret', 'Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(32);
        });
    });

    describe('hmac-sha1', function () {
        it('Should get SHA1 HMAC digest', function () {
            const result = kcrypto.hmac_sha1('secret', 'Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(40);
        });
    });

    describe('hmac-sha256', function () {
        it('Should get SHA256 HMAC digest', function () {
            const result = kcrypto.hmac_sha256('secret', 'Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(64);
        });
    });

    describe('hmac-sha512', function () {
        it('Should get SHA512 HMAC digest', function () {
            const result = kcrypto.hmac_sha512('secret', 'Hello, world.');

            expect(result).to.be.an(Buffer);
            expect(result.toString('hex')).to.have.length(128);
        });
    });

    describe('encrypt', function () {
        it('Should encrypt data', function () {
            const data = 'Hello, world.',
                password = 'password',
                result = kcrypto.encrypt('aes-256-ctr', password, data);

            expect(result).to.have.property('data');
        });
    });

    describe('Should decrypt data', function () {
        it('Should decrypt data', function () {
            const algorithm = 'aes-256-ctr',
                data = 'Hello, world.',
                password = 'password',
                encrypted = kcrypto.encrypt(algorithm, password, data),
                result = kcrypto.decrypt(algorithm, password, encrypted);

            expect(result.toString('utf-8')).to.be(data);
        });
    });

    describe('iv', function () {
        it('Should get iv', function () {
            const result = kcrypto.iv();

            expect(result).to.be.a(Buffer);
            expect(result).to.have.length(12);
        });
    });

    describe('encryptiv', function () {
        describe('Should encrypt data with iv' , function () {
            it('Mode: CBC', function () {
                const data = 'Hello, world.',
                    password = crypto.randomBytes(32),
                    iv = crypto.randomBytes(16),
                    result = kcrypto.encryptiv('aes-256-cbc', password, iv, data);

                expect(result).to.have.property('data');
            });

            it('Mode: GCM', function () {
                const data = 'Hello, world.',
                    password = crypto.randomBytes(32),
                    iv = crypto.randomBytes(12),
                    result = kcrypto.encryptiv('aes-256-gcm', password, iv, data);

                expect(result).to.have.property('data');
                expect(result).to.have.property('tag');
            });
        });
    });

    describe('decryptiv', function () {
        describe('Should decrypt data with iv', function () {
            it('Mode: CBC', function () {
                const algorithm = 'aes-256-cbc',
                    data = 'Hello, world.',
                    password = crypto.randomBytes(32),
                    iv = crypto.randomBytes(16),
                    encrypted = kcrypto.encryptiv(algorithm, password, iv, data),
                    result = kcrypto.decryptiv(algorithm, password, iv, encrypted);

                expect(result.toString('utf-8')).to.be(data);
            });

            it('Mode: GCM', function () {
                const algorithm = 'aes-256-gcm',
                    data = 'Hello, world.',
                    password = crypto.randomBytes(32),
                    iv = crypto.randomBytes(12),
                    encrypted = kcrypto.encryptiv(algorithm, password, iv, data),
                    result = kcrypto.decryptiv(algorithm, password, iv, encrypted);

                expect(result.toString('utf-8')).to.be(data);
            });
        });
    });
});
