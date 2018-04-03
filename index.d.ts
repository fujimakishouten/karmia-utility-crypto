import "@types/node";

declare class KarmiaUtilityCrypto {
    options: object;
    prefix: Buffer;
    counter: Buffer;

    constructor(options?: object);
    hash(algorithm: string, buffer: Buffer|string, encoding?: string): Buffer;
    sha1(buffer: Buffer|string, encoding?: string): Buffer;
    sha256(buffer: Buffer|string, encoding?: string): Buffer;
    sha512(buffer: Buffer|string, encoding?: string): Buffer;
    stretching(algorithm: string, buffer: Buffer|string, count?: number, encoding?: string): Buffer;
    hmac(algorithm: string, password: Buffer|string, buffer: Buffer|string, encoding?: string): Buffer;
    hmac_sha1(secret: Buffer|string, buffer: Buffer|string, encoding?: string): Buffer;
    hmac_sha256(secret: Buffer|string, buffer: Buffer|string, encoding?: string): Buffer;
    hmac_sha512(secret: Buffer|string, buffer: Buffer|string, encoding?: string): Buffer;
    encrypt(algorythm: string, password: Buffer|string, data: Buffer|string, encoding?: string): object;
    decrypt(algorythm: string, password: Buffer|string, buffer: Buffer|object|string, encoding?: string): Buffer;
    iv(): Buffer;
    encryptiv(algorythm: string, password: Buffer|string, iv: Buffer|string, buffer: Buffer|string, encoding?: string): object;
    decryptiv(algorythm: string, password: Buffer|string, iv: Buffer|string, data: Buffer|string, encoding?: string, tag_encoding?: string): Buffer;
}

export = KarmiaUtilityCrypto;
