/**
 * A sliding replay window over a per-direction sequence number.
 *
 * The overlay's control frames carry a frame `seq`. A receiver acts on each one once, so it keeps a
 * window of the last `span` numbers below the highest it has accepted (PROTOCOL.md §5: "act on each
 * `seq` once (a 4096-wide window)"). A number inside the window that was already accepted is a copy;
 * a number older than the window cannot be told from a copy, so it is refused too.
 *
 * Mirrors `ReplayWindow` in `crates/transferd-overlay/src/protocol.rs`.
 */

/** The width the control frames use, in sequence numbers. */
export const CONTROL_WINDOW = 4096;

export class ReplayWindow {
  private readonly span: number;
  private highest: number | null = null;
  /** The accepted numbers inside the window. Anything below it is pruned as the window slides. */
  private readonly seen = new Set<number>();

  constructor(span: number = CONTROL_WINDOW) {
    this.span = Math.max(1, Math.floor(span));
  }

  /** The highest sequence number accepted so far, or null before any. */
  get highestSeen(): number | null {
    return this.highest;
  }

  /** Accept `seq`, or refuse it as a copy or as older than the window. */
  accept(seq: number): boolean {
    if (this.highest === null) {
      this.highest = seq;
      this.seen.add(seq);
      return true;
    }
    if (seq > this.highest) {
      this.highest = seq;
      this.seen.add(seq);
      const floor = Math.max(0, seq - (this.span - 1));
      for (const old of this.seen) {
        if (old < floor) {
          this.seen.delete(old);
        }
      }
      return true;
    }
    if (this.highest - seq >= this.span) {
      return false;
    }
    if (this.seen.has(seq)) {
      return false;
    }
    this.seen.add(seq);
    return true;
  }
}
