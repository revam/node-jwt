
export type Listener<A extends any[]> = (...payload: A) => any;

export class Signal<A extends any[]> {
  public get size(): number {
    return this.listeners.size;
  }

  protected readonly listeners: Set<Listener<A>> = new Set();
  protected readonly onceListeners: Set<Listener<A>> = new Set();

  public add(...listeners: Array<Listener<A>>): this {
    listeners.forEach((l) => this.listeners.add(l));
    return this;
  }

  public addOnce(...listeners: Array<Listener<A>>): this {
    listeners.forEach((l) => { this.listeners.add(l); this.onceListeners.add(l); });
    return this;
  }

  public remove(...listeners: Array<Listener<A>>): this {
    listeners.forEach((l) => { this.listeners.delete(l); this.onceListeners.delete(l); });
    return this;
  }

  public dispatchSync(...payload: A): void {
    if (this.size) {
      for (const listener of this.listeners) {
        listener.apply(undefined, payload);
        this.onceListeners.delete(listener);
      }
    }
  }

  public async dispatchAsync(...payload: A): Promise<void> {
    if (this.size) {
      for (const listener of this.listeners) {
        await listener.apply(undefined, payload);
        this.onceListeners.delete(listener);
      }
    }
  }
}

export interface Signal<A extends any[]> {
  dispatch(...payload: A): void;
}

Signal.prototype.dispatch = Signal.prototype.dispatchSync;
