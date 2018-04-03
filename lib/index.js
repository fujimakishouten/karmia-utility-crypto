/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/* eslint-env es6, mocha, node */
/* eslint-extends: eslint:recommended */
'use strict';



// Variables
const crypto = require('crypto'),
    sha512 = require('js-sha512'),
    karmia_utility_random = require('karmia-utility-random'),
    krandom = karmia_utility_random();


/**
 * KarmiaUtilityCrypto
 *
 * @class
 */
class KarmiaUtilityCrypto {
    /**
     * Constructor
     *
     * @constructs KarmiaUtilityCrypto
     */
    constructor(options) {
        const self = this;
        self.options = options || {};
        self.options.iv = self.options.iv || {};
        self.prefix = Buffer.from(self.options.iv.prefix || crypto.randomBytes(4)).slice(0, 4);
        self.counter = Buffer.alloc(8);

        self.hash = KarmiaUtilityCrypto.hash;
        self.hmac = KarmiaUtilityCrypto.hmac;
        self.encrypt = KarmiaUtilityCrypto.encrypt;
        self.decrypt = KarmiaUtilityCrypto.decrypt;
        self.encryptiv = KarmiaUtilityCrypto.encryptiv;
        self.decryptiv = KarmiaUtilityCrypto.decryptiv;

        self.counter.writeDoubleLE(self.options.iv.start || krandom.integer());
    }

    /**
     * Calculate hash
     *
     * @param   {string} algorithm
     * @param   {Buffer} buffer
     * @param   {string} encoding
     * @returns {string}
     */
    static hash(algorithm, buffer, encoding) {
        const match = algorithm.match(/^sha512[-_/](224|256)$/i);
        encoding = encoding || 'binary';
        buffer = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer, encoding);

        if (match) {
            const hash_function = (256 === Number(match[1])) ? sha512.sha512_256 : sha512.sha512_224;
            return Buffer.from(hash_function(buffer.toString(encoding)), 'hex');
        }

        const hash = crypto.createHash(algorithm);
        hash.update(buffer);

        return hash.digest();
    }

    /**
     * Return SHA-256 hash
     *
     * @param   {string} buffer
     * @param   {string} encoding
     * @returns {string}
     */
    sha1(buffer, encoding) {
        const self = this;

        return self.hash('sha1', buffer, encoding);
    }

    /**
     * Return SHA-256 hash
     *
     * @param   {string} buffer
     * @param   {string} encoding
     * @returns {string}
     */
    sha256(buffer, encoding) {
        const self = this;

        return self.hash('sha256', buffer, encoding);
    }

    /**
     * Return SHA-512 hash
     *
     * @param   {string} buffer
     * @param   {string} encoding
     * @returns {string}
     */
    sha512(buffer, encoding) {
        const self = this;

        return self.hash('sha512', buffer, encoding);
    }

    /**
     * Stretching hash
     *
     * @param   {string} algorithm
     * @param   {Buffer} buffer
     * @param   {Number} count
     * @param   {string} encoding
     * @returns {string}
     */
    stretching (algorithm, buffer, count, encoding) {
        if ('[object String]' === Object.prototype.toString.call(count)) {
            encoding = count;
            count = 1;
        }

        const self = this;
        let result = self.hash(algorithm, buffer, encoding);
        count = count || 1;

        for (let i = 1; i < count - 1; i = i + 1) {
            result = self.hash(algorithm, result);
        }

        return self.hash(algorithm, result);
    }

    /**
     * Calculate HMAC digest
     *
     * @param {string} algorithm
     * @param {Buffer} password
     * @param {Buffer} buffer
     * @param {string} encoding
     * @returns {*}
     */
    static hmac(algorithm, password, buffer, encoding) {
        const secret = Buffer.isBuffer(password) ? password : Buffer.from(password, 'binary'),
            hmac = crypto.createHmac(algorithm, secret);
        buffer = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer, encoding);
        hmac.update(buffer);

        return hmac.digest();
    }

    /**
     * Return HMAC-SHA256 Digest
     *
     * @param {string} secret
     * @param {Buffer} buffer
     * @param {string} encoding
     * @returns {*}
     */
    hmac_sha1(secret, buffer, encoding) {
        const self = this;

        return self.hmac('sha1', secret, buffer, encoding);
    }

    /**
     * Return HMAC-SHA256 Digest
     *
     * @param {string} secret
     * @param {Buffer} buffer
     * @param {string} encoding
     * @returns {*}
     */
    hmac_sha256 (secret, buffer, encoding) {
        const self = this;

        return self.hmac('sha256', secret, buffer, encoding);
    }

    /**
     * Return HMAC-SHA512 Digest
     *
     * @param {string} secret
     * @param {Buffer} buffer
     * @param {string} encoding
     * @returns {*}
     */
    hmac_sha512 (secret, buffer, encoding) {
        const self = this;

        return self.hmac('sha512', secret, buffer, encoding);
    }

    /**
     * Encrypt data without iv
     *
     * @param   {string} algorythm
     * @param   {Buffer} password
     * @param   {Buffer} data
     * @param   {string} encoding
     * @returns {Object}
     */
    static encrypt (algorythm, password, data, encoding) {
        const result = {},
            secret = Buffer.isBuffer(password) ? password : Buffer.from(password, 'binary'),
            cipher = crypto.createCipher(algorythm, secret),
            buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding),
            encrypted = cipher.update(buffer, encoding, 'binary') + cipher.final('binary');
        result.data =  Buffer.from(encrypted, 'binary');

        return result;
    }


    /**
     * Decrypt data without iv
     *
     * @param   {string} algorythm
     * @param   {Buffer} password
     * @param   {Object} buffer
     * @param   {string} encoding
     * @returns {Buffer}
     */
    static decrypt(algorythm, password, buffer, encoding) {
        const secret = Buffer.isBuffer(password) ? password : Buffer.from(password, 'binary'),
            decipher = crypto.createDecipher(algorythm, secret),
            encrypted = ('data' in buffer) ? buffer.data : buffer,
            data = Buffer.isBuffer(encrypted) ? encrypted : Buffer.from(encrypted, encoding);

        return Buffer.from(decipher.update(data, encoding, 'binary') + decipher.final('binary'), 'binary');
    }


    /**
     * Get initial vector
     *
     * @returns {Buffer}
     */
    iv() {
        const self = this,
            result = Buffer.concat([self.prefix, self.counter]),
            current = self.counter.readDoubleLE(),
            next = (Number.MAX_SAFE_INTEGER === current) ? 0 : current + 1;
        if (Number.MAX_SAFE_INTEGER === current) {
            self.counter = Buffer.from(self.options.iv.prefix || crypto.randomBytes(4)).slice(0, 4);
        }

        self.counter.writeDoubleLE(next);

        return result;
    }


    /**
     * Encrypt data with iv
     *
     * @param   {string} algorythm
     * @param   {Buffer} password
     * @param   {Buffer} iv
     * @param   {Buffer} buffer
     * @param   {string} encoding
     * @returns {Object}
     */
    static encryptiv(algorythm, password, iv, buffer, encoding) {
        const result = {},
            mode = algorythm.toLowerCase().substring(algorythm.length - 3),
            secret = Buffer.isBuffer(password) ? password : Buffer.from(password, 'binary'),
            vector = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'binary'),
            cipher = crypto.createCipheriv(algorythm, secret, vector),
            data = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer, encoding),
            encrypted = cipher.update(data, encoding, 'binary') + cipher.final('binary');
        result.data = Buffer.from(encrypted, 'binary');
        if ('gcm' === mode) {
            result.tag = cipher.getAuthTag();
            result.tag = (encoding) ? result.tag.toString(encoding) : result.tag;
        }

        return result;
    }


    /**
     * Decrypt data with iv
     *
     * @param   {string} algorythm
     * @param   {Buffer} password
     * @param   {Buffer} iv
     * @param   {Object} data
     * @param   {string} encoding
     * @param   {string} tag_encoding
     * @returns {Buffer}
     */
    static decryptiv(algorythm, password, iv, data, encoding, tag_encoding) {
        const mode = algorythm.toLowerCase().substring(algorythm.length -3),
            secret = Buffer.isBuffer(password) ? password : Buffer.from(password, 'binary'),
            decipher = crypto.createDecipheriv(algorythm, secret, iv),
            encrypted = ('data' in data) ? data.data : data,
            buffer = Buffer.isBuffer(encrypted) ? encrypted : Buffer.from(encrypted, encoding);
        if ('gcm' === mode) {
            decipher.setAuthTag(Buffer.isBuffer(data.tag) ? data.tag : Buffer.from(data.tag, tag_encoding));
        }

        return Buffer.from(decipher.update(buffer, encoding, 'binary') + decipher.final('binary'), 'binary');
    }
}


// Export module
module.exports = KarmiaUtilityCrypto;


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
