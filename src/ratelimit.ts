/**
 * Per-client-instance rate limiter.
 *
 * Combines a token bucket (burst protection) with three rolling windows
 * (sustained protection: per-minute, per-hour, per-day) and a per-event
 * payload size cap.
 *
 * The limiter exposes an injectable clock (`now` function returning
 * milliseconds, like Date.now) so tests can deterministically advance
 * time without `setTimeout`.
 */

// Defaults applied when a RateLimitConfig field is left undefined or zero.
export const DEFAULT_EVENTS_PER_SECOND = 1;
export const DEFAULT_BURST = 10;
export const DEFAULT_EVENTS_PER_MINUTE = 60;
export const DEFAULT_EVENTS_PER_HOUR = 1000;
export const DEFAULT_EVENTS_PER_DAY = 10000;
export const DEFAULT_MAX_EVENT_BYTES = 65536; // 64 KiB

/** Why an event was dropped (or "ok" if it was allowed). */
export type DropReason =
  | "ok"
  | "burst"
  | "per_minute"
  | "per_hour"
  | "per_day"
  | "payload_too_large";

/** Per-instance rate limiter configuration. All fields optional; defaults shown above. */
export interface RateLimitConfig {
  /** Bypasses all checks when true. */
  disabled?: boolean;
  /** Token bucket refill rate (events/second). */
  eventsPerSecond?: number;
  /** Token bucket capacity. */
  burst?: number;
  /** Rolling 60-second cap. */
  eventsPerMinute?: number;
  /** Rolling 60-minute cap. */
  eventsPerHour?: number;
  /** Rolling 24-hour cap. */
  eventsPerDay?: number;
  /** Per-event JSON size cap in bytes. Set to a negative value to disable. */
  maxEventBytes?: number;
}

/** Cumulative drop counters since client creation. */
export interface RateLimitStats {
  droppedBurst: number;
  droppedPerMinute: number;
  droppedPerHour: number;
  droppedPerDay: number;
  droppedPayloadSize: number;
}

/** Sum of all counters in a stats snapshot. */
export function rateLimitStatsTotal(s: RateLimitStats): number {
  return (
    s.droppedBurst +
    s.droppedPerMinute +
    s.droppedPerHour +
    s.droppedPerDay +
    s.droppedPayloadSize
  );
}

/**
 * Bucketed sliding-window counter.
 *
 * Approximates a true sliding window using `numBuckets` fixed-size
 * sub-windows. Memory and per-call cost are O(numBuckets), which is
 * small (6, 12, or 24 in practice).
 */
export class WindowCounter {
  private readonly bucketDurationMs: number;
  private readonly numBuckets: number;
  private readonly buckets: Array<{ start: number; count: number }>;

  constructor(windowMs: number, numBuckets: number) {
    this.bucketDurationMs = windowMs / numBuckets;
    this.numBuckets = numBuckets;
    this.buckets = Array.from({ length: numBuckets }, () => ({
      start: Number.NEGATIVE_INFINITY,
      count: 0,
    }));
  }

  total(nowMs: number): number {
    const cutoff = nowMs - this.bucketDurationMs * this.numBuckets;
    let sum = 0;
    for (const b of this.buckets) {
      if (b.count > 0 && b.start >= cutoff) sum += b.count;
    }
    return sum;
  }

  add(nowMs: number): void {
    const bucketStart = Math.floor(nowMs / this.bucketDurationMs) * this.bucketDurationMs;
    for (const b of this.buckets) {
      if (b.start === bucketStart) {
        b.count += 1;
        return;
      }
    }
    let oldestIdx = 0;
    for (let i = 1; i < this.buckets.length; i++) {
      if (this.buckets[i]!.start < this.buckets[oldestIdx]!.start) oldestIdx = i;
    }
    this.buckets[oldestIdx] = { start: bucketStart, count: 1 };
  }
}

/**
 * Per-client-instance rate limiter.
 *
 * Combines token bucket (L1), three rolling windows (L2), and a payload
 * size cap (L5). All public methods are safe to call concurrently in
 * single-threaded JS; the structure is also re-entrant safe.
 */
export class RateLimiter {
  private readonly disabled: boolean;
  private readonly now: () => number;
  private readonly eventsPerMs: number; // refill rate
  private readonly burst: number;
  private readonly perMinuteLimit: number;
  private readonly perHourLimit: number;
  private readonly perDayLimit: number;
  private readonly maxBytes: number;

  private tokens: number;
  private lastRefillMs: number;
  private readonly minute = new WindowCounter(60_000, 6);
  private readonly hour = new WindowCounter(3_600_000, 12);
  private readonly day = new WindowCounter(86_400_000, 24);

  private _droppedBurst = 0;
  private _droppedPerMinute = 0;
  private _droppedPerHour = 0;
  private _droppedPerDay = 0;
  private _droppedPayloadSize = 0;

  constructor(config: RateLimitConfig = {}, now: () => number = () => Date.now()) {
    this.disabled = config.disabled === true;
    this.now = now;

    const eventsPerSecond =
      config.eventsPerSecond && config.eventsPerSecond > 0
        ? config.eventsPerSecond
        : DEFAULT_EVENTS_PER_SECOND;
    this.eventsPerMs = eventsPerSecond / 1000;
    this.burst = config.burst && config.burst > 0 ? config.burst : DEFAULT_BURST;
    this.perMinuteLimit =
      config.eventsPerMinute && config.eventsPerMinute > 0
        ? config.eventsPerMinute
        : DEFAULT_EVENTS_PER_MINUTE;
    this.perHourLimit =
      config.eventsPerHour && config.eventsPerHour > 0
        ? config.eventsPerHour
        : DEFAULT_EVENTS_PER_HOUR;
    this.perDayLimit =
      config.eventsPerDay && config.eventsPerDay > 0
        ? config.eventsPerDay
        : DEFAULT_EVENTS_PER_DAY;
    this.maxBytes =
      config.maxEventBytes !== undefined && config.maxEventBytes !== 0
        ? config.maxEventBytes
        : DEFAULT_MAX_EVENT_BYTES;

    this.tokens = this.burst;
    this.lastRefillMs = now();
  }

  /**
   * Returns "ok" if the event should pass; otherwise the specific drop
   * reason. Disabled limiters always return "ok" without modifying any
   * counters. When the event passes, all internal counters are advanced.
   */
  allow(): DropReason {
    if (this.disabled) return "ok";

    const nowMs = this.now();
    const elapsedMs = nowMs - this.lastRefillMs;
    if (elapsedMs > 0) {
      this.tokens = Math.min(this.burst, this.tokens + elapsedMs * this.eventsPerMs);
      this.lastRefillMs = nowMs;
    }

    if (this.tokens < 1) {
      this._droppedBurst += 1;
      return "burst";
    }
    if (this.minute.total(nowMs) >= this.perMinuteLimit) {
      this._droppedPerMinute += 1;
      return "per_minute";
    }
    if (this.hour.total(nowMs) >= this.perHourLimit) {
      this._droppedPerHour += 1;
      return "per_hour";
    }
    if (this.day.total(nowMs) >= this.perDayLimit) {
      this._droppedPerDay += 1;
      return "per_day";
    }

    this.tokens -= 1;
    this.minute.add(nowMs);
    this.hour.add(nowMs);
    this.day.add(nowMs);
    return "ok";
  }

  /** Increment the payload-too-large counter without consuming token capacity. */
  recordPayloadDrop(): void {
    this._droppedPayloadSize += 1;
  }

  /** Snapshot of cumulative drop counters. */
  stats(): RateLimitStats {
    return {
      droppedBurst: this._droppedBurst,
      droppedPerMinute: this._droppedPerMinute,
      droppedPerHour: this._droppedPerHour,
      droppedPerDay: this._droppedPerDay,
      droppedPayloadSize: this._droppedPayloadSize,
    };
  }

  /** Configured per-event size cap, or 0 if disabled (limiter or negative cap). */
  maxEventBytes(): number {
    if (this.disabled) return 0;
    if (this.maxBytes < 0) return 0;
    return this.maxBytes;
  }
}

/**
 * Parse a Retry-After header value to milliseconds.
 *
 * Supports both delta-seconds (`"5"`) and HTTP-date forms.
 * Returns 0 for missing, unparseable, or non-positive values.
 */
export function parseRetryAfterMs(header: string | null | undefined, nowMs: number = Date.now()): number {
  if (!header) return 0;
  const trimmed = header.trim();
  if (!trimmed) return 0;
  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && Number.isInteger(seconds)) {
    return seconds > 0 ? seconds * 1000 : 0;
  }
  const t = Date.parse(trimmed);
  if (!Number.isFinite(t)) return 0;
  const delta = t - nowMs;
  return delta > 0 ? delta : 0;
}
