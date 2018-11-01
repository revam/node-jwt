/**
 * The value is only truly available when awaited or wrapped in a promise.
 */
export type Await<T> = T | Promise<T> | PromiseLike<T>;

/**
 * Basic error handler.
 */
export type ErrorHandler = (error: Error | any) => any;

type MethodNames<T> = { [P in keyof T]: T[P] extends (...args: any[]) => any ? P : never; }[keyof T];

/**
 * Filter all methods on `T`, excluding any key from `K`.
 */
export type Methods<T, K extends keyof T = never> = Pick<T, Exclude<MethodNames<T>, K>>;

/**
 * Filter all properties on `T`, excluding any key from `K`.
 */
export type Properties<T, K extends keyof T = never> = Pick<T, Exclude<keyof T, MethodNames<T> | K>>;

/**
 * Find subject and additional properties to include in token.
 * @param args Arguments as defined in `A`.
 * @returns subject, subject and additional properties, or undefined.
 */
export type FindSubjectFunction<A extends any[], T, K extends keyof Properties<T> = never>
  = (...args: A) => Await<string | [string, Pick<Properties<T>, K>?] | undefined>;

/**
 * Verify if subject is still valid.
 * @param subject Subject of JWT token.
 * @returns subject is valid.
 */
export type VerifySubjectFunction = (subject: string) => Await<boolean>;

/**
 * JSON Web Token, with additional properties from `T` as restricted by `K`.
 */
export type JWT<T, K extends keyof Properties<T> = never> = Readonly<Pick<Properties<T>, K>> & {
  /**
   * JWT Identifier
   */
  readonly jti: string;
  /**
   * Subject
   */
  readonly sub: string;
  /**
   * Issuer
   */
  readonly iss: string;
  /**
   * Audience (as an array)
   */
  readonly aud: string[];
  /**
   * Expiration Time (in seconds)
   */
  readonly exp: number;
  /**
   * Issued At (in seconds)
   */
  readonly iat: number;
};

export interface JWTManagerOptions<A extends any[], T, K extends keyof Properties<T> = never> {
  /**
   * Signature algorithm. Could be one of these values :
   * - HS256:    HMAC using SHA-256 hash algorithm (default)
   * - HS384:    HMAC using SHA-384 hash algorithm
   * - HS512:    HMAC using SHA-512 hash algorithm
   * - RS256:    RSASSA using SHA-256 hash algorithm
   * - RS384:    RSASSA using SHA-384 hash algorithm
   * - RS512:    RSASSA using SHA-512 hash algorithm
   * - ES256:    ECDSA using P-256 curve and SHA-256 hash algorithm
   * - ES384:    ECDSA using P-384 curve and SHA-384 hash algorithm
   * - ES512:    ECDSA using P-521 curve and SHA-512 hash algorithm
   * - none:     No digital signature or MAC value included
   */
  algorithm?: "HS256" | "HS384" | "HS512" | "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "none";
  /**
   * Valid audience. Defaults to the same as property `issuer`.
   */
  audience?: string | string[];
  /**
   * Issuer. Defaults to `"localhost"`.
   */
  issuer?: string;
  /**
   *
   */
  expireTime?: string | number;
  /**
   *
   */
  clockTolerance?: number;
  /**
   * Handle errors.
   */
  onError?: ErrorHandler;
  /**
   * Either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.
   */
  secretOrPublicKey?: string | Buffer;
  /**
   * Either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.
   */
  secretOrPrivateKey?: string | Buffer;
  /**
   * Alternate storage for keeping valid JWT ids.
   */
  storage?: JWTIdStore;
  /**
   * Find subject and additional properties to include in token.
   */
  findSubject: FindSubjectFunction<A, T, K>;
  /**
   * Verify if subject is still valid.
   */
  verifySubject?: VerifySubjectFunction;
}

/**
 * Simple interface for storing any valid JWT identifiers.
 */
export interface JWTIdStore {
  /**
   * Add `identifier` to store.
   * @param identifier Token identifier
   * @param expireTime Expire time, in seconds.
   */
  add(identifier: string, expireTime?: number): Promise<void>;
  /**
   * Clear all idenifiers from store.
   */
  clear(): Promise<void>;
  /**
   * Invalidate `identifier` from store.
   * @param identifier Token identifier
   * @returns `identifier` is now invalid.
   */
  invalidate(identifier: string): Promise<boolean>;
  /**
   * Verify if `identifier` is still valid.
   * @param identifier Token identifier
   * @returns `identifier` is still valid.
   */
  verify(identifier: string): Promise<boolean>;
}
