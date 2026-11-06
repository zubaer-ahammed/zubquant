export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface SigningKeyPair {
  verifyKey: string;
  signingKey: string;
}

export interface SealOptions {
  aad?: string | Uint8Array;
  ephemeralSeed?: Uint8Array;
  nonce?: Uint8Array;
}

export interface OpenOptions {
  aad?: string | Uint8Array;
  returnBytes?: boolean;
  parseJson?: boolean;
}

export interface VerifyOptions {
  returnBytes?: boolean;
  parseJson?: boolean;
}

export interface VerifyResult<T = string> {
  valid: boolean;
  payload: T | null;
}

export declare function generateKeyPair(seed32?: Uint8Array): KeyPair;
export declare function seal(data: string | Record<string, unknown> | Uint8Array, publicKey: string, options?: SealOptions): Promise<string>;
export declare function open<T = string>(envelope: string, privateKey: string, options?: OpenOptions): Promise<T>;
export declare function protectPrivateKey(privateKey: string, passphrase: string, iterations?: number): Promise<string>;
export declare function unlockPrivateKey(lockedEnvelope: string, passphrase: string): Promise<string>;

export declare function generateSigningKeyPair(seed32?: Uint8Array): SigningKeyPair;
export declare function sign(payload: string | Record<string, unknown> | Uint8Array, signingKey: string): string;
export declare function verify<T = string>(signedToken: string, verifyKey: string, options?: VerifyOptions): VerifyResult<T>;

export declare function toBase64Url(bytes: Uint8Array): string;
export declare function fromBase64Url(str: string): Uint8Array;
export declare function randomBytes(len: number): Uint8Array;

