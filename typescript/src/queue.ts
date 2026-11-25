/**
 * A FIFO that can be awaited: `next()` resolves with the oldest item, and waits for one when none is queued.
 * The overlay session hands its events through one of these, as the reference hands them through a channel.
 */
export class EventQueue<T> {
  private readonly items: T[] = [];
  private readonly waiters: Array<(item: T) => void> = [];

  push(item: T): void {
    const waiter = this.waiters.shift();
    if (waiter !== undefined) {
      waiter(item);
    } else {
      this.items.push(item);
    }
  }

  next(): Promise<T> {
    if (this.items.length > 0) {
      return Promise.resolve(this.items.shift() as T);
    }
    return new Promise<T>((resolve) => this.waiters.push(resolve));
  }

  get size(): number {
    return this.items.length;
  }
}
