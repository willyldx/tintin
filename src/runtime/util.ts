import { timingSafeEqual } from "node:crypto";

export function nowMs(): number {
  return Date.now();
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function timingSafeEqualString(a: string, b: string): boolean {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  if (aa.length !== bb.length) return false;
  return timingSafeEqual(aa, bb);
}

export function chunkText(text: string, maxChars: number): string[] {
  const out: string[] = [];
  let remaining = text;
  while (remaining.length > maxChars) {
    const slice = remaining.slice(0, maxChars);
    const cut = Math.max(slice.lastIndexOf("\n\n"), slice.lastIndexOf("\n"), slice.lastIndexOf(" "));
    const idx = cut > Math.floor(maxChars * 0.5) ? cut : maxChars;
    out.push(remaining.slice(0, idx).trimEnd());
    remaining = remaining.slice(idx);
  }
  if (remaining.trim().length > 0) out.push(remaining.trim());
  return out;
}

export class RateLimiter {
  private readonly minIntervalMs: number;
  private nextAtMs = 0;

  constructor(ratePerSec: number) {
    this.minIntervalMs = ratePerSec > 0 ? 1000 / ratePerSec : 0;
  }

  async waitTurn(): Promise<void> {
    if (this.minIntervalMs <= 0) return;
    const now = nowMs();
    const wait = Math.max(0, this.nextAtMs - now);
    this.nextAtMs = Math.max(now, this.nextAtMs) + this.minIntervalMs;
    if (wait > 0) await sleep(wait);
  }
}

export class TaskQueue {
  private readonly concurrency: number;
  private running = 0;
  private readonly pending: Array<() => Promise<void>> = [];

  constructor(concurrency: number) {
    this.concurrency = Math.max(1, concurrency);
  }

  enqueue(task: () => Promise<void>) {
    this.pending.push(task);
    void this.drain();
  }

  private async drain() {
    while (this.running < this.concurrency && this.pending.length > 0) {
      const task = this.pending.shift();
      if (!task) return;
      this.running++;
      (async () => {
        try {
          await task();
        } finally {
          this.running--;
          void this.drain();
        }
      })().catch(() => {});
    }
  }
}

