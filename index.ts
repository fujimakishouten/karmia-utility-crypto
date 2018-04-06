/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/* eslint-env es6, mocha, node */
/* eslint-extends: eslint:recommended */
'use strict';



// Import modules
import KarmiaUtilityRandom = require("karmia-utility-random");
import crypto = require("crypto");
const sha512 = require("js-sha512");


// Variables
const random = new KarmiaUtilityRandom();


declare interface IV {
    prefix?: Buffer;
    start?: number;
}

declare interface EncryptedData {
    data: Buffer|string;
    tag?: Buffer|string;
}


/**
 * KarmiaUtilityCrypto
 *
 * @class
 */
class KarmiaUtilityCrypto {
    /**
     * Properties
     */
    public options: {iv?: IV};
    public prefix: Buffer;
    public counter: Buffer;

    public hash = KarmiaUtilityCrypto.hash;
    public hmac = KarmiaUtilityCrypto.hmac;
    public encrypt = KarmiaUtilityCrypto.encrypt;
    public decrypt = KarmiaUtilityCrypto.decrypt;
    public encryptiv = KarmiaUtilityCrypto.encryptiv;
    public decryptiv = KarmiaUtilityCrypto.decryptiv;

    /**
     * Constructor
     *
     * @constructs KarmiaUtilityCrypto
     */
    constructor(options?: {iv?: IV}) {
        this.options = options || {};
        this.options.iv = this.options.iv || {} as IV;
        this.prefix = Buffer.from(this.options.iv.prefix || crypto.randomBytes(4)).slice(0, 4);
        this.counter = Buffer.alloc(8);

        this.hash = KarmiaUtilityCrypto.hash;
        this.hmac = KarmiaUtilityCrypto.hmac;
        this.encrypt = KarmiaUtilityCrypto.encrypt;
        this.decrypt = KarmiaUtilityCrypto.decrypt;
        this.encryptiv = KarmiaUtilityCrypto.encryptiv;
        this.decryptiv = KarmiaUtilityCrypto.decryptiv;

        this.counter.writeDoubleLE(this.options.iv.start || random.integer(), 0);
    }

    /**
     * Calculate hash
     *
     * @param   {string} algorithm
     * @param   {Buffer|string} buffer
     * @param   {string} [encoding]
     * @returns {Buffer}
     */
    static hash(algorithm: string, buffer: Buffer|string, encoding?: string): Buffer {
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
     * @param   {Buffer|string} buffer
     * @param   {string} [encoding]
     * @returns {Buffer}
     */
    sha1(buffer: Buffer|string, encoding?: string): Buffer {
        const self = this;

        return self.hash('sha1', buffer, encoding);
    }

    /**
     * Return SHA-256 hash
     *
     * @param   {Buffer|string} buffer
     * @param   {string} [encoding]
     * @returns {Buffer}
     */
    sha256(buffer: Buffer|string, encoding?: string): Buffer {
        const self = this;

        return self.hash('sha256', buffer, encoding);
    }

    /**
     * Return SHA-512 hash
     *
     * @param   {Buffer|string} buffer
     * @param   {string} [encoding]
     * @returns {Buffer}
     */
    sha512(buffer: Buffer|string, encoding?: string): Buffer {
        const self = this;

        return self.hash('sha512', buffer, encoding);
    }

    /**
     * Stretching hash
     *
     * @param   {string} algorithm
     * @param   {Buffer|string} buffer
     * @param   {Number} [count=1]
     * @param   {string} [encoding]
     * @returns {Buffer}
     */
    stretching (algorithm: string, buffer: Buffer|string, count=1, encoding?: string) {
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
     * @param {Buffer|string} password
     * @param {Buffer|string} buffer
     * @param {string} [encoding]
     * @returns {Buffer}
     */
    static hmac(algorithm: string, password: Buffer|string, buffer: Buffer|string, encoding?: string): Buffer {
        const secret = Buffer.isBuffer(password) ? password : Buffer.from(password, 'binary'),
            hmac = crypto.createHmac(algorithm, secret);
        buffer = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer, encoding);
        hmac.update(buffer);

        return hmac.digest();
    }

    /**
     * Return HMAC-SHA256 Digest
     *
     * @param {Buffer|string} secret
     * @param {Buffer|string} buffer
     * @param {string} [encoding]
     * @returns {*}
     */
    hmac_sha1(secret: Buffer|string, buffer: Buffer|string, encoding?: string): Buffer {
        const self = this;

        return self.hmac('sha1', secret, buffer, encoding);
    }

    /**
     * Return HMAC-SHA256 Digest
     *
     * @param {Buffer|string} secret
     * @param {Buffer|string} buffer
     * @param {string} [encoding]
     * @returns {Buffer}
     */
    hmac_sha256 (secret: Buffer|string, buffer: Buffer|string, encoding?: string): Buffer {
        const self = this;

        return self.hmac('sha256', secret, buffer, encoding);
    }

    /**
     * Return HMAC-SHA512 Digest
     *
     * @param {Buffer|string} secret
     * @param {Buffer|string} buffer
     * @param {string} [encoding]
     * @returns {Buffer}
     */
    hmac_sha512 (secret: Buffer|string, buffer: Buffer|string, encoding?: string): Buffer {
        const self = this;

        return self.hmac('sha512', secret, buffer, encoding);
    }

    /**
     * Encrypt data without iv
     *
     * @param   {string} algorythm
     * @param   {Buffer|string} password
     * @param   {Buffer|string} data
     * @param   {string} [encoding]
     * @returns {Object}
     */
    static encrypt (algorythm: string, password: Buffer|string, data: Buffer|string, encoding?: string): EncryptedData {
        const result = {} as EncryptedData,
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
     * @param   {Buffer|string} password
     * @param   {Buffer|Object|string} data
     * @param   {string} [encoding]
     * @returns {Buffer}
     */
    static decrypt(algorythm: string, password: Buffer|string, data: EncryptedData, encoding?: string): Buffer {
        const secret = Buffer.isBuffer(password) ? password : Buffer.from(password, 'binary'),
            decipher = crypto.createDecipher(algorythm, secret),
            encrypted = ('data' in data) ? data.data : data,
            buffer = Buffer.isBuffer(encrypted) ? encrypted : Buffer.from(encrypted, encoding);

        return Buffer.from(decipher.update(buffer, encoding, 'binary') + decipher.final('binary'), 'binary');
    }


    /**
     * Get initial vector
     *
     * @returns {Buffer}
     */
    iv(): Buffer {
        const self = this,
            result = Buffer.concat([self.prefix, self.counter]),
            current = self.counter.readDoubleLE(0),
            next = (Number.MAX_SAFE_INTEGER === current) ? 0 : current + 1;
        if (Number.MAX_SAFE_INTEGER === current) {
            self.counter = Buffer.from(self.options.iv.prefix || crypto.randomBytes(4)).slice(0, 4);
        }

        self.counter.writeDoubleLE(next, 0);

        return result;
    }


    /**
     * Encrypt data with iv
     *
     * @param   {string} algorythm
     * @param   {Buffer|string} password
     * @param   {Buffer|string} iv
     * @param   {Buffer|string} buffer
     * @param   {string} [encoding]
     * @returns {Object}
     */
    static encryptiv(algorythm: string, password: Buffer|string, iv: Buffer|string, buffer: Buffer|string, encoding?: string): EncryptedData {
        const result = {} as EncryptedData,
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
     * @param   {Buffer|string} password
     * @param   {Buffer|string} iv
     * @param   {EncryptedData} data
     * @param   {string} [encoding]
     * @param   {string} [tag_encoding]
     * @returns {Buffer}
     */
    static decryptiv(algorythm: string, password: Buffer|string, iv: Buffer|string, data: EncryptedData, encoding?: string, tag_encoding?: string): Buffer {
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
export = KarmiaUtilityCrypto;


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
