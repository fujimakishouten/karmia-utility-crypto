declare module KarmiaUtility {
    export class KarmiaUtilityCrypto {
        options: Object;
        prefix: Buffer;
        counter: Buffer;

        constructor(options: Object);
        hash(algorithm: string, buffer: Buffer|string, encoding: null|string|undefined): Buffer;
        sha1(buffer: Buffer|string, encoding: null|string|undefined): Buffer;
        sha256(buffer: Buffer|string, encoding: null|string|undefined): Buffer;
        sha512(buffer: Buffer|string, encoding: null|string|undefined): Buffer;
        stretching(algorithm: string, buffer: Buffer|string, count: null|number|undefined, encoding: null|string|undefined): Buffer;
        hmac(algorithm: string, password: Buffer|string, buffer: Buffer|string, encoding: null|string|undefined): Buffer;
        hmac_sha1(secret: Buffer|string, buffer: Buffer|string, encoding: null|string|undefined): Buffer;
        hmac_sha256(secret: Buffer|string, buffer: Buffer|string, encoding: null|string|undefined): Buffer;
        hmac_sha512(secret: Buffer|string, buffer: Buffer|string, encoding: null|string|undefined): Buffer;
        encrypt(algorithm: string, password: Buffer|string, data: Buffer|string, encoding: null|string|undefined): Object;
        decrypt(algorithm: string, password: Buffer|string, buffer: Buffer|Object, encoding: null|string|undefined): Buffer;
        iv(): Buffer;
        encrypt(algorithm: string, password: Buffer|string, iv: Buffer|string, data: Buffer|string, encoding: null|string|undefined): Object;
        decrypt(algorithm: string, password: Buffer|string, iv: Buffer|string, sbuffer: Buffer|Object, encoding: null|string|undefined): Buffer;
    }
}
