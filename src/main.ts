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
 * Tokens.
 *
 * @remarks
 *
 * Additional fields added to token is left to the application to
 * choose.
 */
export class JWTManager<TArgs extends any[], T = never, TKeys extends keyof Properties<T> = keyof Properties<T>> {
  /**
   * Either the secret for HMAC algorithms, or the PEM encoded public key for
   * RSA and ECDSA.
   */
  private readonly secretOrPublicKey: Buffer;

  /**
   * Either the secret for HMAC algorithms, or the PEM encoded private key for
   * RSA and ECDSA.
   */
  private readonly secretOrPrivateKey: Buffer;

  /**
   * Algorithm used for generating signature.
   */
  private readonly algorithm: string;

  /**
   * Audience.
   */
  private readonly audience: string[];

  /**
   * The domain issuing JSON Web Tokens (JWTs).
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
  private readonly find: JWTManager.FindSubjectFunction<TArgs, T, TKeys>;

  /**
   * Verify if subject is still valid.
   */
  private readonly verifyCustom?: JWTManager.VerifyFunction<T, TKeys>;

  /**
   * Generate an unique identifier for JWT token.
   */
  private readonly generateID: JWTManager.GenerateIDFunction;

  /**
   * Dispatched on successful generation of a new token.
   *
   * @remarks
   *
   * Errors thrown by listeners are handled in the `onError` signal.
   */
  public readonly onGenerate: Signal<[JWT<T, TKeys>]> = new Signal();

  /**
   * Dispatched on successful verification of a token.
   *
   * @remarks
   *
   * Errors thrown by listeners are handled in the `onError` signal.
   */
  public readonly onVerify: Signal<[JWT<T, TKeys>]> = new Signal();

  /**
   * Dispatched on successful invalidation of a token.
   *
   * @remarks
   *
   * Errors thrown by listeners are handled in the `onError` signal.
   */
  public readonly onInvalidate: Signal<[JWT<T, TKeys>]> = new Signal();

  /**
   * Dispatched when any error is thrown from other class methods and/or
   * signals.
   */
  public readonly onError: Signal<[any, JWT<T, TKeys>?]> = new Signal();

  /**
   * Create a new instance of {@link JWTManager}.
   *
   * @param options - Mandatory {@link JWTManager.Options | options}.
   */
  public constructor(options: JWTManager.Options<TArgs, T, TKeys>);
  public constructor({
    algorithm = "HS256",
    clockTolerance = 10,
    expireTime = 3600, // 60 * 60 = 3,600
    find,
    generateID,
    authority,
    issuer = "localhost",
    audience = issuer,
    secretOrPublicKey = "",
    secretOrPrivateKey = secretOrPublicKey,
    verify: verifyCustom,
  }: JWTManager.Options<TArgs, T, TKeys>) {
    this.algorithm = algorithm;
    this.find = find;
    this.verifyCustom = verifyCustom;
    this.generateID = generateID;
    this.issuer = issuer;
    this.audience = typeof audience === "string" ? [audience] : audience;
    this.expireTime = expireTime;
    this.expireTolerance = clockTolerance;
    this.id = authority || new MemoryAuthority();
    this.secretOrPublicKey = secretOrPublicKey instanceof Buffer
      ? secretOrPublicKey : Buffer.from(secretOrPublicKey);
    this.secretOrPrivateKey = secretOrPrivateKey instanceof Buffer
      ? secretOrPrivateKey : Buffer.from(secretOrPrivateKey);
  }

  /**
   * Create a new token if {@link JWT.sub | subject} can be extracted from
   * {@link JWTManager.GenerateOptions | options}.
   * {@link JWTManager.GenerateOptions.args | Arguments} must be supplied.
   *
   * @param options - Mandatory {@link JWTManager.GenerateOptions | options}.
   * @returns Returns a new JWT token if successfull, otherwise returns
   *          `undefined`.
   */
  public async generate(options: JWTManager.GenerateOptions<TArgs>): Promise<string | undefined> {
    let jwt: JWT<T, TKeys> | undefined;
    try {
      const result = await this.find(...options.args);
      if (result) {
        let subject: string | undefined;
        let payload: Properties<T, TKeys> | {} = {};
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
          jwtid: this.generateID(),
          subject,
        };
        if (options.notBefore) {
          signOptions.notBefore = options.notBefore;
        }
        const token = await sign(payload, this.secretOrPrivateKey, signOptions);
        jwt = decode<JWT<T, TKeys>>(token);
        await this.onGenerate.dispatchAsync(jwt);
        return token;
      }
    } catch (error) {
      await this.onError.dispatchAsync(error, jwt);
    }
  }

  /**
   * Verifies the signature integrity, experation time and, if defined, custom
   * logic provided in {@link JWTManager.Options.verify | options}.
   *
   * @param token - JSON Web Token (JWT) to vefiy and decode.
   * @param audience - Audience to check token for. Defaults to provided
   *                   audience for manager.
   * @returns Returns the decoded contents of token if `token` is successfully
   *          verified, returns `undefined` otherwise.
   */
  public async verify(token: string, audience: string | string[] = this.audience): Promise<JWT<T, TKeys> | undefined> {
    let jwt: JWT<T, TKeys> | undefined;
    try {
      if (!token || !token.length) {
        throw new TypeError("Token must be provided and not be empty.");
      }
      jwt = await verify<JWT<T, TKeys>>(token, this.secretOrPublicKey, {
        audience,
        clockTolerance: this.expireTolerance,
        issuer: this.issuer,
      });
      if (typeof jwt === "object") {
        if (! await this.id.validate(jwt.jti)) {
          throw new JsonWebTokenError("invalid jwt identifier");
        }
        if (this.verifyCustom && ! await this.verifyCustom(jwt)) {
          throw new JsonWebTokenError("invalid jwt in custom rules");
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
   * Verifies and retrns the decoded token extracted from a valid
   * [authorization header](https://developer.mozilla.org/docs/Web/HTTP/Headers/Authorization).
   *
   * @remarks
   *
   * Will not extract or verify a token if header is not valid, or if token is
   * invalid.
   *
   * Also see {@link JWTManager.verify}.
   *
   * @param header - Value of '[Authorization](https://developer.mozilla.org/docs/Web/HTTP/Headers/Authorization)'
   *                 header.
   * @param audience - Audience to check for. Defaults to provided audience for
   *                 manager.
   * @returns Returns the decoded contents of token if `token` is successfully
   *          verified, returns `undefined` otherwise.
   */
  public async verifyHeader(header: string = "", audience?: string | string[]): Promise<JWT<T, TKeys> | undefined> {
    const [schemaValue, token] = header.split(" ");
    if (schemaValue.toLowerCase() === "bearer" && token) {
      return this.verify(token, audience);
    }
  }

  /**
   * Invalidates given JWT-token, either encoded or decoded.
   *
   * @param jwt - JSON Web Token to invalidate, either stringified or decoded.
   * @returns Returns `true` if token was successfully invalidated with
   *          {@link JWTAuthority | id-authorities}, returns false otherwise.
   */
  public async invalidate(jwt?: string | JWT<T, TKeys>): Promise<boolean> {
    if (typeof jwt === "string") {
      jwt = this.decode(jwt);
    }
    // The storage may throw, so we wrap it in a try..catch clause
    try {
      if (jwt && jwt.jti && (jwt.exp ? await this.id.invalidate(jwt.jti, jwt.exp) : true)) {
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
   *
   * @param token - Stringified JSON Web Token (JWT) to decode.
   */
  public decode(token?: string): JWT<T, TKeys> | undefined {
    if (typeof token === "string" && token.length > 0) {
      return decode<JWT<T, TKeys>>(token);
    }
  }
}

export namespace JWTManager {
  /**
   * Options for constructor of {@link JWTManager}.
   */
  export interface Options<TArgs extends any[], T = never, TKeys extends keyof Properties<T> = keyof Properties<T>> {
    /**
     * Signature algorithm.
     *
     * @remarks
     *
     * Could be one of these values :
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
     * Valid audience for token.
     *
     * @remarks
     *
     * Defaults to the same as value as field `issuer`.
     */
    audience?: string | string[];
    /**
     * Issuer authority.
     *
     * @remarks
     *
     * Defaults to `"localhost"`.
     */
    issuer?: string;
    /**
     * Token expiration time, expressed in seconds or a string describing a
     * timespan, e.g. "1 min".
     *
     * @remarks
     *
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
     * Either the secret for HMAC algorithms, or the PEM encoded public key for
     * RSA and ECDSA.
     */
    secretOrPublicKey?: string | Buffer;
    /**
     * Either the secret for HMAC algorithms, or the PEM encoded private key for
     * RSA and ECDSA.
     */
    secretOrPrivateKey?: string | Buffer;
    /**
     * Keeps track of all invalidated tokens until their TTL ends, and helps
     * validate and invalidate JWT identifiers.
     *
     * @remarks
     *
     * Will use an in-memory based authority if none is supplied.
     */
    authority?: JWTAuthority;
    /**
     * Find subject and additional properties to include in token.
     */
    find: FindSubjectFunction<TArgs, T, TKeys>;
    /**
     * Verify if subject is still valid.
     *
     * @remarks
     *
     * This is custom logic in addition to the default verification logic,
     * i.e. verify custom fields and/or values in decoded token.
     */
    verify?: VerifyFunction<T, TKeys>;
    /**
     * Generate an unique identifier for JWT token.
     */
    generateID: GenerateIDFunction;
  }

  /**
   * Options for {@link JWTManager.generate}.
   */
  export interface GenerateOptions<TArgs extends any[]> {
    /**
     * Arguments are forwarded to the `FindSubjectFunction` registered with the
     * manager.
     */
    args: TArgs;
    /**
     * Not valid before this timespan have past.
     * Expressed in seconds or a string describing a timespan, e.g. "1 min".
     */
    notBefore?: string | number;
  }

  /**
   * Find subject and additional properties to include in token.
   *
   * @param args - Arguments as defined in `A`.
   * @returns subject, subject and additional properties, or undefined.
   */
  export type FindSubjectFunction<TArgs extends any[], T = never, TKeys extends keyof Properties<T> = keyof Properties<T>>
    = (...args: TArgs) => Await<string | [string, Properties<T, TKeys>?] | ({ sub: string } & Properties<T, TKeys>) | undefined>;

  /**
   * Verify if token is still valid.
   *
   * @param jwt - Decoded JSON Web Token (JWT)
   * @returns token is valid.
   */
  export type VerifyFunction<T = never, TKeys extends keyof Properties<T> = keyof Properties<T>>
    = (jwt: JWT<T, TKeys>) => Await<boolean | undefined>;

  /**
   * Generate an unique identifier for JWT token.
   *
   * @returns an unique identifier for token.
   */
  export type GenerateIDFunction = () => string;

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
 * Filter selected properties on `T`, as restricted by `K`.
 */
export type Properties<T, TKeys extends keyof T = keyof T> = Pick<T, Exclude<TKeys, MethodNames<T>>>;

/**
 * JSON Web Token, with additional properties from `T`, as restricted by `K`.
 */
export type JWT<T = never, TKeys extends keyof Properties<T> = keyof Properties<T>> = Readonly<Properties<T, TKeys>> & {
  /**
   * Unique identifier for this JSON Web Token (JWT).
   */
  readonly jti: string;
  /**
   * Subject associated with this JSON Web Token (JWT).
   */
  readonly sub: string;
  /**
   * Domain of issuer for this JSON Web Token (JWT).
   */
  readonly iss: string;
  /**
   * Audience domains for this JSON Web Token (JWT).
   */
  readonly aud: string[];
  /**
   * Timestamp this JSON Web Token (JWT) will expire, given in seconds.
   */
  readonly exp: number;
  /**
   * Timestamp this JSON Web Token (JWT) was issued, given in seconds.
   */
  readonly iat: number;
  /**
   * Timestamp from when this JSON Web Token (JWT) is valid, given in seconds.
   */
  readonly nbf?: number;
};

/**
 * Keeps track of all invalidated tokens until their TTL ends, and helps
 * validate and invalidate JWT identifiers.
 */
export interface JWTAuthority {
  /**
   * Invalidate `jti` from authorities.
   *
   * @remarks
   *
   * The expire time is also provided, in cases where the key is to-be kept for
   * a limited period of time.
   *
   * @param jti - JSON Web Token (JWT) identifier.
   * @param exp - Timestamp token will naturally expire, given in seconds.
   * @returns Returns `true` if invalidatation was successful, returns `false`
   *          otherwise.
   */
  invalidate(jti: string, exp: number): Promise<boolean>;
  /**
   * Validate `jti` with authorities.
   *
   * @param jti - JSON Web Token (JWT) identifier.
   * @returns Returns `true` if validation was successful, returns `false`
   *          otherwise.
   */
  validate(jti: string): Promise<boolean>;
}

/**
 * Simple implementation of an in-memory {@link JWTAuthority}.
 */
class MemoryAuthority implements JWTAuthority {
  /* @internal */
  private readonly map: Map<string, NodeJS.Timeout> = new Map();

  public async validate(key: string): Promise<boolean> {
    return !this.map.has(key);
  }

  public async invalidate(key: string, exp: number): Promise<boolean> {
    if (this.map.has(key)) {
      return false;
    }
    const ref = setTimeout(() => this.map.delete(key), exp * 1000);
    this.map.set(key, ref);
    return true;
  }

  public async clear(): Promise<void> {
    this.map.clear();
  }
}
