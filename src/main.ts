import {
  decode as DECODE,
  JsonWebTokenError,
  sign as SIGN,
  SignOptions,
  verify as VERIFY,
  VerifyOptions,
} from "jsonwebtoken";
import { promisify } from "util";
import { Signal } from "./signal";

export * from "./signal";

const sign: <T>(payload: T, secret: Buffer, options?: SignOptions) => Promise<string>
  = promisify<any, Buffer, string>(SIGN);
const verify: <T>(token: string, secret: Buffer, options?: VerifyOptions) => Promise<T>
  = promisify<string, Buffer, any>(VERIFY);
const decode: <T>(token: string) => T
  = (token) => DECODE(token, { json: true }) as any;

/**
 * Simple class responsable for creating, verifying and invalidating JSON Web
 * Tokens. Additional fields added to token is left to the application to choose.
 */
export class JWTManager<A extends any[], T = never, K extends keyof Properties<T> = keyof Properties<T>> {
  /**
   * Either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.
   */
  private readonly secretOrPublicKey: Buffer;

  /**
   * Either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.
   */
  private readonly secretOrPrivateKey: Buffer;

  /**
   * Algorithm.
   */
  private readonly algorithm: string;

  /**
   * Audience.
   */
  private readonly audience: string[];

  /**
   * Issuer.
   */
  protected readonly issuer: string;

  /**
   * Expire time.
   */
  private readonly expireTime: string | number;

  /**
   * Clock tolerance for expire time.
   */
  protected readonly expireTolerance: number;

  /**
   * Id authority.
   */
  protected readonly id: JWTAuthority;

  /**
   * Handles all errors thrown internally.
   */

  /**
   * Find subject and additional properties to include in token.
   */
  private readonly findSubject: JWTManager.FindSubjectFunction<A, T, K>;

  /**
   * Verify if subject is still valid.
   */
  private readonly verifySubject?: JWTManager.VerifyFunction<T, K>;

  /**
   * Generate an unique identifier for JWT token.
   */
  private readonly generateID: JWTManager.GenerateIDFunction;

  /**
   * Dispatched on successful generation of a new token.
   * Errors thrown by listeners are handled in the `onError` signal.
   */
  public readonly onGenerate: Signal<[JWT<T, K>]> = new Signal();

  /**
   * Dispatched on successful verification of a token.
   * Errors thrown by listeners are handled in the `onError` signal.
   */
  public readonly onVerify: Signal<[JWT<T, K>]> = new Signal();

  /**
   * Dispatched on successful invalidation of a token.
   * Errors thrown by listeners are handled in the `onError` signal.
   */
  public readonly onInvalidate: Signal<[JWT<T, K>]> = new Signal();

  /**
   * Dispatched when any error is thrown from other methods and/or signals.
   */
  public readonly onError: Signal<[any, JWT<T, K>?]> = new Signal();

  public constructor(options: JWTManager.Options<A, T, K>);
  public constructor({
    algorithm = "HS256",
    clockTolerance = 10,
    expireTime = 3600, // 60 * 60 = 3,600
    findSubject,
    generateID,
    authority: storage,
    issuer = "localhost",
    audience = issuer,
    secretOrPublicKey = "",
    secretOrPrivateKey = secretOrPublicKey,
    verifySubject,
  }: JWTManager.Options<A, T, K>) {
    this.algorithm = algorithm;
    this.findSubject = findSubject;
    this.verifySubject = verifySubject;
    this.generateID = generateID;
    this.issuer = issuer;
    this.audience = typeof audience === "string" ? [audience] : audience;
    this.expireTime = expireTime;
    this.expireTolerance = clockTolerance;
    this.id = storage || new MemoryAuthority();
    this.secretOrPublicKey = secretOrPublicKey instanceof Buffer
      ? secretOrPublicKey : Buffer.from(secretOrPublicKey);
    this.secretOrPrivateKey = secretOrPrivateKey instanceof Buffer
      ? secretOrPrivateKey : Buffer.from(secretOrPrivateKey);
  }

  /**
   * Create a new token for user if subject can be abstracted from
   * @param options Generate options. Args must be supplied.
   * @returns a new JWT token if successful.
   */
  public async generate(options: JWTManager.GenerateOptions<A>): Promise<string | undefined> {
    let jwt: JWT<T, K> | undefined;
    try {
      const result = await this.findSubject(...options.args);
      if (result) {
        let subject: string | undefined;
        let payload: Properties<T, K> | {} = {};
        if (typeof result === "object") {
          if (result instanceof Array) {
            subject = result[0];
            if (result[1]) {
              payload = result[1];
            }
          }
          else {
            subject = result.sub;
            delete result.sub;
            payload = result;
          }
        }
        else {
          subject = result;
        }
        const signOptions: SignOptions = {
          algorithm: this.algorithm,
          audience: this.audience,
          expiresIn: this.expireTime,
          issuer: this.issuer,
          jwtid: await this.generateID(),
          subject,
        };
        if (options.notBefore) {
          signOptions.notBefore = options.notBefore;
        }
        const token = await sign(payload, this.secretOrPrivateKey, signOptions);
        jwt = decode<JWT<T, K>>(token);
        await this.onGenerate.dispatchAsync(jwt);
        return token;
      }
    } catch (error) {
      await this.onError.dispatchAsync(error, jwt);
    }
  }

  /**
   * Verifies the JWT-token.
   * @param token JSON Web Token to verify
   * @param audience Audience to check for. Defaults to provided audience for
   *                 manager.
   */
  public async verify(token: string = "", audience: string | string[] = this.audience): Promise<JWT<T, K> | undefined> {
    let jwt: JWT<T, K> | undefined;
    try {
      jwt = await verify<JWT<T, K>>(token, this.secretOrPublicKey, {
        audience,
        clockTolerance: this.expireTolerance,
        issuer: this.issuer,
      });
      if (typeof jwt === "object") {
        if (! await this.id.validate(jwt.jti)) {
          throw new JsonWebTokenError("invalid jwt identifier");
        }
        if (this.verifySubject && ! await this.verifySubject(jwt)) {
          throw new JsonWebTokenError("invalid jwt subject");
        }
        await this.onVerify.dispatchAsync(jwt);
        return jwt;
      }
    } catch (error) {
      await this.onError.dispatchAsync(error, jwt);
      // invalidate token if any verification errors was thrown.
      if (error instanceof JsonWebTokenError) {
        await this.invalidate(token);
      }
    }
  }

  /**
   * Verifies the JWT-token extracted *only** from a valid authorization header.
   * @param header Value of 'Authorization' header.
   * @param audience Audience to check for. Defaults to provided audience for
   *                 manager.
   */
  public async verifyHeader(header: string = "", audience?: string | string[]): Promise<JWT<T, K> | undefined> {
    const [schemaValue, token] = header.split(" ");
    if (schemaValue.toLowerCase() === "bearer" && token) {
      return this.verify(token, audience);
    }
  }

  /**
   * Invalidates given JWT-token.
   * @param jwt JSON Web Token to invalidate, either stringified or decoded.
   */
  public async invalidate(jwt?: string | JWT<T, K>): Promise<boolean> {
    if (typeof jwt === "string") {
      jwt = this.decode(jwt);
    }
    // The storage may throw, so we wrap it in a try..catch clause
    try {
      if (jwt && jwt.jti && await this.id.invalidate(jwt.jti, jwt.exp * 1000)) {
        await this.onInvalidate.dispatchAsync(jwt);
        return true;
      }
    } catch (error) {
      await this.onError.dispatchAsync(error, jwt);
    }
    return false;
  }

  /**
   * Decode a token without verifying if it is valid or safe to use.
   * @param token JSON Web Token to decode.
   */
  public decode(token: string = ""): JWT<T, K> | undefined {
    return token ? decode<JWT<T, K>>(token) : undefined;
  }
}

export namespace JWTManager {
  export interface Options<A extends any[], T = never, K extends keyof Properties<T> = keyof Properties<T>> {
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
     * Valid audience for token. Defaults to the same as value as field `issuer`.
     */
    audience?: string | string[];
    /**
     * Issuer authority. Defaults to `"localhost"`.
     */
    issuer?: string;
    /**
     * Token expiration time.
     * Expressed in seconds or a string describing a timespan, e.g. "1 min".
     * Defaults to `3600`.
     */
    expireTime?: string | number;
    /**
     * The clock tolerance for time compare. For applications with system-clocks
     * not 100% in sync with each other.
     * Expressed in seconds.
     */
    clockTolerance?: number;
    /**
     * Either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.
     */
    secretOrPublicKey?: string | Buffer;
    /**
     * Either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.
     */
    secretOrPrivateKey?: string | Buffer;
    /**
     * Keeps track of all invalidated tokens until their TTL ends, and helps
     * validate and invalidate JWT identifiers.
     *
     * Will use an in-memory based authority if none is supplied.
     */
    authority?: JWTAuthority;
    /**
     * Find subject and additional properties to include in token.
     */
    findSubject: FindSubjectFunction<A, T, K>;
    /**
     * Verify if subject is still valid.
     */
    verifySubject?: VerifyFunction;
    /**
     * Generate an unique identifier for JWT token.
     */
    generateID: GenerateIDFunction;
  }

  export interface GenerateOptions<A extends any[]> {
    /**
     * Arguments are forwarded to the `FindSubjectFunction` registered with the
     * manager.
     */
    args: A;
    /**
     * Not valid before this timespan have past.
     * Expressed in seconds or a string describing a timespan, e.g. "1 min".
     */
    notBefore?: string | number;
  }

  /**
   * Find subject and additional properties to include in token.
   * @param args Arguments as defined in `A`.
   * @returns subject, subject and additional properties, or undefined.
   */
  export type FindSubjectFunction<A extends any[], T = never, K extends keyof Properties<T> = keyof Properties<T>>
    = (...args: A) => Await<string | [string, Pick<Properties<T>, K>?] | ({ sub: string } & Pick<Properties<T>, K>) | undefined>;

  /**
   * Verify if token is still valid.
   * @param jwt Decoded JSON Web Token (JWT)
   * @returns token is valid.
   */
  export type VerifyFunction<T = never, K extends keyof Properties<T> = keyof Properties<T>>
    = (jwt: JWT<T, K>) => Await<boolean | undefined>;

  /**
   * Generate an unique identifier for JWT token.
   * @returns an unique identifier for token.
   */
  export type GenerateIDFunction = () => Await<string>;

}

/**
 * The value is only truly available when wrapped in a promise and resolved.
 */
export type Await<T> = T | Promise<T> | PromiseLike<T>;

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
 * JSON Web Token, with additional properties from `T` as restricted by `K`.
 */
export type JWT<T = never, K extends keyof Properties<T> = keyof Properties<T>> = Readonly<Pick<Properties<T>, K>> & {
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
  /**
   * Not (valid) Before (in seconds)
   */
  readonly nbf?: number;
};

/**
 * Keeps track of all invalidated tokens until their TTL ends, and helps
 * validate and invalidate JWT identifiers.
 */
export interface JWTAuthority {
  /**
   * Invalidate {@link identifier} from authorities. An estimated time-to-live
   * is also provided.
   *
   * @param jti JSON Web Token (JWT) identifier, as generated by the manager.
   * @param eTTL Estimated Time-To-Live, in milliseconds.
   * @returns Returns {@link true} if {@link JWTId} has been invalidated,
   *          returns {@link false} otherwise.
   */
  invalidate(jti: string, eTTL: number): Promise<boolean>;
  /**
   * Validate if {@link identifier} is a valid JSON Web Token (JWT) id with
   * authorities.
   *
   * @param jti JSON Web Token (JWT) identifier, as generated by the manager.
   * @returns Returns {@link true} if {@link JWTId} is still valid,
   *          returns {@link false} otherwise.
   */
  validate(jti: string): Promise<boolean>;
}

/**
 * Simple implementation of an in-memory `JWTIdStore`.
 */
class MemoryAuthority implements JWTAuthority {
  /* @internal */
  private readonly map: Map<string, number | undefined> = new Map();

  public async validate(key: string): Promise<boolean> {
    const timestamp = this.map.get(key);
    if (timestamp) {
      const now = Math.floor(Date.now() / 1000);
      // Check if the timestamp is less than the current time,
      if (timestamp < now) {
        // and remove timestamp if true.
        this.map.delete(key);
      }
      return false;
    }
    return true;
  }

  public async invalidate(key: string): Promise<boolean> {
    return this.map.delete(key);
  }

  public async clear(): Promise<void> {
    this.map.clear();
  }
}
