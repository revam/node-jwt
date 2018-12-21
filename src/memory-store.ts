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

  private expire(key: string): boolean {
    const timestamp = this.map.get(key);
    if (timestamp) {
      // Substract the tolerance from the current time.
      const now = Math.floor(Date.now() / 1000) - this.clockTolerance;
      // And check if the timestamp is less than the current time.
      if (timestamp < now) {
        this.map.delete(key);
        return true;
      }
    }
    return false;
  }
}
