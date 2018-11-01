import { JWTIdStore } from "./types";

/**
 * Simple implementation of an in-memory `JWTIdStore`.
 */
export class MemoryStore implements JWTIdStore {
  /* @internal */
  private readonly map: Map<string, number | undefined> = new Map();

  public constructor(private readonly clockTolerance: number = 10) {}

  public async add(key: string, expireTime?: number): Promise<void> {
    this.map.set(key, expireTime);
  }

  public async verify(key: string): Promise<boolean> {
    return !this.expire(key) && this.map.has(key);
  }

  public async invalidate(key: string): Promise<boolean> {
    return this.map.delete(key);
  }

  public async clear(): Promise<void> {
    this.map.clear();
  }

  private expire(key): boolean {
    const now = Math.floor(Date.now() / 1000) + this.clockTolerance;
    const expire = this.map.get(key);
    if (expire && expire <= now) {
      this.map.delete(key);
      return true;
    }
    return false;
  }
}
