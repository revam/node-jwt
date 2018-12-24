import {
  decode as DECODE,
  JsonWebTokenError,
  sign as SIGN,
  SignOptions,
  verify as VERIFY,
  VerifyOptions,
} from "jsonwebtoken";
import { promisify } from "util";
import { v4 } from "uuid";
import { MemoryStore } from "./memory-store";
import {
  ErrorHandler,
  FindSubjectFunction,
  JWT,
  JWTGenerateOptions,
  JWTIdStore,
  JWTManagerOptions,
  Properties,
  VerifySubjectFunction,
} from "./types";

export * from "./memory-store";
export * from "./types";

const sign: <T>(payload: T, secret: string | Buffer, options?: SignOptions) => Promise<string>
  = promisify<any, string | Buffer, string>(SIGN);
const verify: <T>(token: string, secret: string | Buffer, options?: VerifyOptions) => Promise<T>
  = promisify(VERIFY);
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
   * Storage for valid JWT identifiers.
   */
  protected readonly storage: JWTIdStore;

  /**
   * Handles all errors thrown internally.
   */
  private readonly onError: ErrorHandler<T, K>;

  /**
   * Find subject and additional properties to include in token.
   */
  private readonly findSubject: FindSubjectFunction<A, T, K>;

  /**
   * Verify if subject is still valid.
   */
  private readonly verifySubject?: VerifySubjectFunction;

  public constructor(options: JWTManagerOptions<A, T, K>);
  public constructor({
    algorithm = "HS256",
    clockTolerance = 10,
    expireTime = 3600, // 60 * 60 = 3,600
    findSubject,
    storage,
    issuer = "localhost",
    audience = issuer,
    onError,
    secretOrPublicKey = "",
    secretOrPrivateKey = secretOrPublicKey,
    verifySubject,
  }: JWTManagerOptions<A, T, K>) {
    this.algorithm = algorithm;
    this.findSubject = findSubject;
    this.verifySubject = verifySubject;
    this.issuer = issuer;
    this.audience = typeof audience === "string" ? [audience] : audience;
    this.expireTime = expireTime;
    this.expireTolerance = clockTolerance;
    this.storage = storage || new MemoryStore(clockTolerance);
    this.onError = typeof onError === "function" ? onError :  (error) => console.error(error);
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
  public async generate(options: JWTGenerateOptions<A>): Promise<string | undefined> {
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
          jwtid: v4(),
          subject,
        };
        if (options.notBefore) {
          signOptions.notBefore = options.notBefore;
        }
        const token = await sign(payload, this.secretOrPrivateKey, signOptions);
        jwt = decode<JWT<T, K>>(token);
        await this.storage.add(jwt.jti, jwt.exp);
        return token;
      }
    } catch (error) {
      await this.onError(error, jwt);
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
        if (! await this.storage.verify(jwt.jti)) {
          throw new JsonWebTokenError("invalid jwt identifier");
        }
        if (this.verifySubject && ! await this.verifySubject(jwt.sub)) {
          throw new JsonWebTokenError("invalid jwt subject");
        }
        return jwt;
      }
    } catch (error) {
      await this.onError(error, jwt);
      // invalidate token if any verification errors was thrown.
      if (error instanceof JsonWebTokenError) {
        await this.invalidate(token);
      }
    }
  }

  /**
   * Verifies the JWT-token extracted *only** from a valid authorization header.
   * @param header Value of 'Authorization' header.
   * @param schema Valid authorization schema to use.
   */
  public async verifyHeader(header: string = "", schema: string = "bearer"): Promise<JWT<T, K> | undefined> {
    const [schemaValue, token] = header.split(" ");
    if (schemaValue.toLowerCase() === schema && token) {
      return this.verify(token);
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
      if (jwt && jwt.jti && await this.storage.invalidate(jwt.jti)) {
        return true;
      }
    } catch (error) {
      await this.onError(error, jwt);
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

/**
 * Pick all properties in `keys` from `t`.
 */
export function pick<T, K extends keyof T>(t: T, keys: K[]): Pick<T, K> {
  return keys.reduce((o, k) => k in t && (o[k] = t[k]) && o || o, {} as Pick<T, K>);
}
