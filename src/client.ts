/**
 * WireLog analytics client for Node.js and browsers.
 * Zero runtime dependencies — uses native fetch and Web Crypto.
 *
 * In browsers, automatically piggybacks on the wirelog.js script tag's
 * localStorage identity (device_id, user_id), manages session_id, and
 * buffers `track()` events with async batch flushes.
 *
 * In Node.js, `track()` now also buffers events by default and flushes
 * them in batches (matching browser behavior). Call `close()` to flush
 * remaining events on shutdown.
 */

import {
  RateLimiter,
  parseRetryAfterMs,
  type DropReason,
  type RateLimitConfig,
  type RateLimitStats,
} from "./ratelimit.js";

export type { DropReason, RateLimitConfig, RateLimitStats };

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

function isBrowserEnv(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined";
}

const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 min, matches wirelog.js
const BATCH_INTERVAL = 2000; // 2s, matches wirelog.js
const BATCH_MAX = 10;
const QUEUE_MAX = 500;
const RETRY_MAX = 3;
const RETRY_BASE_MS = 1000;
const MAX_BATCH_API_SIZE = 2000; // server's MaxBatchSize

const ATTR_PARAMS = [
  "utm_source",
  "utm_medium",
  "utm_campaign",
  "utm_term",
  "utm_content",
  "gclid",
  "fbclid",
] as const;

const SESSION_ID_KEY = "wl_sid";
const SESSION_LAST_KEY = "wl_slast";
const ATTR_FIRST_KEY = "wl_attr_first";
const ATTR_LAST_KEY = "wl_attr_last";
const ATTR_SYNC_USER_KEY = "wl_attr_sync_user";

const _crypto: Crypto | undefined = globalThis.crypto;

function uuid(): string {
  if (_crypto?.randomUUID) return _crypto.randomUUID();
  // Fallback for Node 18 where globalThis.crypto is undefined in ESM.
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

/** Generate a 24-char hex ID, matching wirelog.js format. */
function hexId(): string {
  if (_crypto?.getRandomValues) {
    const arr = new Uint8Array(12);
    _crypto.getRandomValues(arr);
    return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  // Fallback for Node 18.
  let hex = "";
  for (let i = 0; i < 24; i++) hex += Math.floor(Math.random() * 16).toString(16);
  return hex;
}

// Safe storage wrappers — never throw.
function lsGet(key: "wl_did" | "wl_uid"): string | null {
  if (!isBrowserEnv()) return null;
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function lsSet(key: "wl_did" | "wl_uid", value: string): void {
  if (!isBrowserEnv()) return;
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage full or blocked — best-effort */
  }
}

function lsRemove(key: "wl_did" | "wl_uid"): void {
  if (!isBrowserEnv()) return;
  try {
    localStorage.removeItem(key);
  } catch {
    /* best-effort */
  }
}

function ssGet(key: string): string | null {
  if (!isBrowserEnv()) return null;
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function ssSet(key: string, value: string): void {
  if (!isBrowserEnv()) return;
  try {
    sessionStorage.setItem(key, value);
  } catch {
    /* best effort */
  }
}

function ssRemove(key: string): void {
  if (!isBrowserEnv()) return;
  try {
    sessionStorage.removeItem(key);
  } catch {
    /* best effort */
  }
}

function readSessionJSON(key: string): Record<string, string> {
  const raw = ssGet(key);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object") {
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof v === "string" && v !== "") out[k] = v;
      }
      return out;
    }
  } catch {
    // ignore parse failure
  }
  return {};
}

function writeSessionJSON(key: string, value: Record<string, string>): void {
  ssSet(key, JSON.stringify(value));
}

function hasOwnKeys(obj: Record<string, unknown>): boolean {
  for (const k in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) return true;
  }
  return false;
}

function cloneMap<T>(obj?: Record<string, T>): Record<string, T> {
  if (!obj || typeof obj !== "object") return {};
  return { ...obj };
}

function extractAttributionFromLocation(): Record<string, string> {
  if (!isBrowserEnv()) return {};
  const out: Record<string, string> = {};
  try {
    const params = new URLSearchParams(window.location.search || "");
    for (const key of ATTR_PARAMS) {
      const value = params.get(key);
      if (value) out[key] = value;
    }
  } catch {
    // URLSearchParams unsupported or blocked
  }
  return out;
}

function applyAttributionProps(
  target: Record<string, unknown>,
  prefix: string,
  attrs: Record<string, string>,
): void {
  for (const key of ATTR_PARAMS) {
    const value = attrs[key];
    if (value) target[`${prefix}${key}`] = value;
  }
}

/**
 * Measure the UTF-8 byte size of an event's JSON serialization.
 * Returns -1 when the value can't be serialized (circular references,
 * BigInt, etc.) so callers can treat it as a payload drop and avoid
 * passing the event further into the queue / send pipeline.
 */
function measurePayloadSize(value: unknown): number {
  let json: string;
  try {
    json = JSON.stringify(value);
  } catch {
    return -1;
  }
  if (typeof json !== "string") return -1;
  try {
    return new TextEncoder().encode(json).length;
  } catch {
    return json.length;
  }
}

function envVar(name: string): string | undefined {
  if (isBrowserEnv()) return undefined;
  try {
    return typeof process !== "undefined" ? process.env?.[name] : undefined;
  } catch {
    return undefined;
  }
}

export interface WireLogConfig {
  /** API key (pk_, sk_, or aat_). Falls back to WIRELOG_API_KEY env var in Node. */
  apiKey?: string;
  /** API base URL. Falls back to WIRELOG_HOST env var in Node. Defaults to https://api.wirelog.ai. */
  host?: string;
  /**
   * Error callback for background flush errors (Node.js only).
   * In browsers, errors are handled internally with retry logic.
   */
  onError?: (err: Error) => void;
  /** Disable all tracking. track() becomes a no-op. Useful for tests. */
  disabled?: boolean;
  /**
   * Per-instance rate limiter configuration. Defaults are conservative
   * (1 evt/s burst capacity 10, 60/min, 1000/hr, 10000/day, 64 KiB/event).
   * Set `rateLimit: { disabled: true }` to bypass.
   */
  rateLimit?: RateLimitConfig;
  /**
   * Internal: clock override used by tests. Returns milliseconds (like
   * Date.now). Not part of the stable API.
   * @internal
   */
  _now?: () => number;
}

export interface TrackEvent {
  event_type: string;
  user_id?: string;
  device_id?: string;
  session_id?: string;
  clientOriginated?: boolean;
  time?: string;
  event_properties?: Record<string, unknown>;
  user_properties?: Record<string, unknown>;
  insert_id?: string;
}

export interface TrackResult {
  accepted: number;
  /** True when events were queued locally (not yet acknowledged by the API). */
  buffered?: boolean;
}

export interface IdentifyParams {
  user_id: string;
  device_id?: string;
  user_properties?: Record<string, unknown>;
  user_property_ops?: {
    $set?: Record<string, unknown>;
    $set_once?: Record<string, unknown>;
    $add?: Record<string, number>;
    $unset?: string[];
  };
}

export interface IdentifyResult {
  ok: boolean;
}

export interface QueryOptions {
  format?: "llm" | "json" | "csv";
  limit?: number;
  offset?: number;
}

type FlushReason = "manual" | "batch" | "interval" | "retry" | "hidden" | "pagehide" | "close";

/** Error thrown when the WireLog API returns a non-2xx response.
 *
 * `retryAfterMs` is set to the parsed Retry-After header (in
 * milliseconds) on 429 responses, or 0 if absent or unparseable.
 */
export class WireLogError extends Error {
  status: number;
  retryAfterMs: number;

  constructor(status: number, message: string, retryAfterMs = 0) {
    super(`WireLog API ${status}: ${message}`);
    this.name = "WireLogError";
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

/** Reported to onError when an event is dropped by the rate limiter. */
export class RateLimitedError extends Error {
  reason: DropReason;
  constructor(reason: DropReason) {
    super(`wirelog: event dropped (rate limited: ${reason})`);
    this.name = "RateLimitedError";
    this.reason = reason;
  }
}

/** Reported to onError when an event exceeds the per-event size cap. */
export class PayloadTooLargeError extends Error {
  size: number;
  limit: number;
  constructor(size: number, limit: number) {
    super(`wirelog: event dropped (payload ${size} bytes exceeds ${limit})`);
    this.name = "PayloadTooLargeError";
    this.size = size;
    this.limit = limit;
  }
}

export class WireLog {
  private apiKey: string;
  private host: string;
  private _initialized = false;
  private _disabled: boolean;
  private _onError: ((err: Error) => void) | undefined;

  // Browser identity state — populated only when running in a browser.
  private _deviceId: string | null = null;
  private _sessionId: string | null = null;
  private _lastActivity = 0;
  private _userId: string | null = null;

  // Tracks the user_id for which attribution has already been merged.
  private _attrIdentified: string | null = null;
  private _queue: TrackEvent[] = [];
  private _flushTimer: ReturnType<typeof setTimeout> | null = null;
  private _retryTimer: ReturnType<typeof setTimeout> | null = null;
  private _retryCount = 0;
  private _flushPromise: Promise<TrackResult> | null = null;
  private _browserHooksInstalled = false;
  private _closed = false;
  private _limiter: RateLimiter;

  constructor(config: WireLogConfig = {}) {
    this.apiKey = config.apiKey ?? envVar("WIRELOG_API_KEY") ?? "";
    this.host = (config.host ?? envVar("WIRELOG_HOST") ?? "https://api.wirelog.ai").replace(/\/$/, "");
    this._disabled = config.disabled ?? false;
    this._onError = config.onError;
    this._limiter = new RateLimiter(config.rateLimit, config._now);
    if (this.apiKey) this._initialized = true;

    if (isBrowserEnv()) {
      // Piggyback on wirelog.js localStorage keys if present.
      this._deviceId = lsGet("wl_did");
      if (!this._deviceId) {
        this._deviceId = hexId();
        lsSet("wl_did", this._deviceId);
      }
      this._userId = lsGet("wl_uid") || null;
      // Session is hydrated lazily from sessionStorage in browserIdentity(),
      // so we always share the same session as wirelog.js.
      this._attrIdentified = ssGet(ATTR_SYNC_USER_KEY) || null;

      // Keep attribution pending state up to date even before identify.
      this.captureAttribution();
      this.installBrowserFlushHooks();
    }
  }

  /** Current device ID (browser-only, null in Node). */
  get deviceId(): string | null {
    return this._deviceId;
  }

  /** Current user ID (browser-only, null in Node until identify). */
  get userId(): string | null {
    return this._userId;
  }

  /** Initialize the client with config. Use with the singleton: `wl.init({ apiKey: "pk_..." })`. */
  init(config: WireLogConfig): void {
    if (config.apiKey) this.apiKey = config.apiKey;
    if (config.host) this.host = config.host.replace(/\/$/, "");
    if (config.onError) this._onError = config.onError;
    if (config.disabled !== undefined) this._disabled = config.disabled;
    // Rebuild the limiter when the caller supplies new config or a clock
    // override. This is the documented entry point for `wl.init({ rateLimit: ... })`
    // on the singleton — silently ignoring it here breaks user expectations.
    if (config.rateLimit !== undefined || config._now !== undefined) {
      this._limiter = new RateLimiter(config.rateLimit, config._now);
    }
    this._initialized = true;
  }

  /**
   * Track a single event. Buffered in both browsers and Node.js.
   * Returns `{ accepted: 1, buffered: true }` immediately without waiting for the network.
   */
  async track(event: TrackEvent): Promise<TrackResult> {
    if (this._disabled || this._closed) return { accepted: 0 };

    // L1+L2: rate limit BEFORE any enrichment so a hot loop is cheap.
    const reason = this._limiter.allow();
    if (reason !== "ok") {
      this.reportError(new RateLimitedError(reason));
      return { accepted: 0 };
    }

    const body = this.enrichEvent(event);
    if (!this.ensureInitialized()) {
      return { accepted: 0, buffered: true };
    }

    // L5: per-event payload size cap (after enrichment so we measure
    // the true wire size, before queueing).
    const maxBytes = this._limiter.maxEventBytes();
    if (maxBytes > 0) {
      const size = measurePayloadSize(body);
      if (size < 0) {
        // Unserializable (circular ref, BigInt, …). Treat as a payload
        // drop so it never wedges the inflight flush path later.
        this._limiter.recordPayloadDrop();
        this.reportError(new PayloadTooLargeError(0, maxBytes));
        return { accepted: 0 };
      }
      if (size > maxBytes) {
        this._limiter.recordPayloadDrop();
        this.reportError(new PayloadTooLargeError(size, maxBytes));
        return { accepted: 0 };
      }
    }

    this.enqueueBrowserEvents([body]);
    if (this._queue.length >= BATCH_MAX) {
      void this.flushQueuedEvents("batch");
    } else {
      this.scheduleFlush();
    }
    return { accepted: 1, buffered: true };
  }

  /** Snapshot of per-instance rate limiter drop counters. */
  rateLimitStats(): RateLimitStats {
    return this._limiter.stats();
  }

  /**
   * Track multiple events in one request (up to 2000).
   *
   * Each event is checked individually against the per-instance rate
   * limiter (L1+L2) and the per-event payload size cap (L5). Events
   * that fail either check are silently dropped from the batch and
   * counted in `rateLimitStats()`. Batches larger than 2000 events
   * throw (matches the server's `MaxBatchSize`). When the client is
   * disabled or closed, returns `{ accepted: 0 }` without sending.
   */
  async trackBatch(events: TrackEvent[]): Promise<TrackResult> {
    if (this._disabled || this._closed) return { accepted: 0 };
    if (events.length > MAX_BATCH_API_SIZE) {
      throw new Error(
        `wirelog: batch of ${events.length} events exceeds max ${MAX_BATCH_API_SIZE}`,
      );
    }

    const maxBytes = this._limiter.maxEventBytes();
    const survivors: TrackEvent[] = [];
    for (const e of events) {
      const reason = this._limiter.allow();
      if (reason !== "ok") {
        this.reportError(new RateLimitedError(reason));
        continue;
      }
      const enriched = this.enrichEvent(e);
      if (maxBytes > 0) {
        const size = measurePayloadSize(enriched);
        if (size < 0) {
          this._limiter.recordPayloadDrop();
          this.reportError(new PayloadTooLargeError(0, maxBytes));
          continue;
        }
        if (size > maxBytes) {
          this._limiter.recordPayloadDrop();
          this.reportError(new PayloadTooLargeError(size, maxBytes));
          continue;
        }
      }
      survivors.push(enriched);
    }

    if (survivors.length === 0) return { accepted: 0 };

    const body = isBrowserEnv()
      ? { events: survivors, clientOriginated: true }
      : { events: survivors };
    return this.post("/track", body) as Promise<TrackResult>;
  }

  /**
   * Flush buffered events immediately.
   * Blocks until the current queue is drained.
   */
  async flush(): Promise<TrackResult> {
    if (this._disabled) return { accepted: 0 };
    if (!this.ensureInitialized()) return { accepted: 0, buffered: true };
    return this.flushQueuedEvents("manual");
  }

  /**
   * Flush remaining events and stop the client.
   * After close(), track() calls are silently dropped.
   * Idempotent — safe to call multiple times.
   */
  async close(): Promise<TrackResult> {
    if (this._closed || this._disabled) return { accepted: 0 };
    this._closed = true;
    this.clearFlushTimer();
    this.clearRetryTimer();
    if (!this._queue.length) return { accepted: 0 };
    return this.flushQueuedEvents("close");
  }

  /** Run a pipe DSL query. Returns Markdown (default), JSON, or CSV. */
  async query(q: string, opts?: QueryOptions): Promise<unknown> {
    return this.post("/query", {
      q,
      format: opts?.format ?? "llm",
      limit: opts?.limit ?? 100,
      offset: opts?.offset ?? 0,
    });
  }

  /**
   * Bind a device to a user and/or set profile properties.
   * In browsers, also persists user_id to localStorage so it's shared
   * with the wirelog.js script tag and survives page reloads.
   */
  async identify(params: IdentifyParams): Promise<IdentifyResult> {
    const userID = (params.user_id || "").trim();
    if (!userID) {
      throw new Error("wirelog: identify requires non-empty user_id");
    }

    // identify counts against the same per-instance rate limiter as
    // track so a remount loop can't open unbounded identify requests.
    const reason = this._limiter.allow();
    if (reason !== "ok") {
      throw new RateLimitedError(reason);
    }

    let mergedOps = params.user_property_ops;
    let shouldMarkAttrSynced = false;

    if (isBrowserEnv()) {
      // Re-read device ID from localStorage in case wirelog.js changed it.
      const storedDid = lsGet("wl_did");
      if (storedDid) this._deviceId = storedDid;

      this._userId = userID;
      lsSet("wl_uid", userID);

      const attrs = this.captureAttribution();
      if (this._attrIdentified !== userID) {
        const setOnce = cloneMap(mergedOps?.$set_once);
        const set = cloneMap(mergedOps?.$set);

        applyAttributionProps(setOnce, "initial_", attrs.first);
        applyAttributionProps(set, "last_", attrs.last);

        mergedOps = {
          ...(mergedOps || {}),
          ...(hasOwnKeys(setOnce) ? { $set_once: setOnce } : {}),
          ...(hasOwnKeys(set) ? { $set: set } : {}),
        };

        shouldMarkAttrSynced = hasOwnKeys(attrs.first) || hasOwnKeys(attrs.last);
      }
    }

    const body: IdentifyParams = {
      ...params,
      user_id: userID,
      device_id: params.device_id || this._deviceId || undefined,
      user_property_ops: mergedOps,
    };

    const result = (await this.post("/identify", body)) as IdentifyResult;

    if (isBrowserEnv() && shouldMarkAttrSynced) {
      this._attrIdentified = userID;
      ssSet(ATTR_SYNC_USER_KEY, userID);
    }

    return result;
  }

  /** Clear identity state. In browsers, generates a new device ID and clears user. */
  reset(): void {
    if (!isBrowserEnv()) return;
    this._userId = null;
    this._sessionId = null;
    this._lastActivity = 0;
    this._attrIdentified = null;
    this._queue = [];
    this.clearFlushTimer();
    this.clearRetryTimer();
    this._retryCount = 0;

    // Match wirelog.js reset: removeItem (not set-empty) for localStorage,
    // clear all session state from sessionStorage.
    lsRemove("wl_did");
    lsRemove("wl_uid");
    ssRemove(SESSION_ID_KEY);
    ssRemove(SESSION_LAST_KEY);
    ssRemove(ATTR_SYNC_USER_KEY);
    ssRemove(ATTR_FIRST_KEY);
    ssRemove(ATTR_LAST_KEY);

    this._deviceId = hexId();
    lsSet("wl_did", this._deviceId);
  }

  private ensureInitialized(): boolean {
    if (this._initialized) return true;
    console.warn("wirelog: call wl.init({ apiKey }) before tracking events");
    return false;
  }

  private enqueueBrowserEvents(events: TrackEvent[]): void {
    for (const event of events) {
      if (this._queue.length >= QUEUE_MAX) {
        this._queue.shift();
      }
      this._queue.push(event);
    }
  }

  private scheduleFlush(): void {
    if (this._flushTimer || !this._queue.length) return;
    this._flushTimer = setTimeout(() => {
      this._flushTimer = null;
      void this.flushQueuedEvents("interval");
    }, BATCH_INTERVAL);
  }

  private clearFlushTimer(): void {
    if (!this._flushTimer) return;
    clearTimeout(this._flushTimer);
    this._flushTimer = null;
  }

  private clearRetryTimer(): void {
    if (!this._retryTimer) return;
    clearTimeout(this._retryTimer);
    this._retryTimer = null;
  }

  private scheduleRetry(retryAfterMs = 0): void {
    if (this._retryTimer || !this._queue.length) return;
    // L6: prefer the server-provided Retry-After when present; jitter
    // is unnecessary because the server has already chosen the time.
    const baseDelay =
      retryAfterMs > 0
        ? Math.min(30000, retryAfterMs)
        : Math.min(30000, RETRY_BASE_MS * Math.pow(2, this._retryCount));
    const jitter = retryAfterMs > 0 ? 0 : Math.floor(Math.random() * 250);
    this._retryTimer = setTimeout(() => {
      this._retryTimer = null;
      void this.flushQueuedEvents("retry");
    }, baseDelay + jitter);
  }

  private installBrowserFlushHooks(): void {
    if (!isBrowserEnv() || this._browserHooksInstalled) return;
    this._browserHooksInstalled = true;

    if (typeof window.addEventListener === "function") {
      window.addEventListener("pagehide", () => {
        void this.flushQueuedEvents("pagehide");
      });
    }

    if (typeof document.addEventListener === "function") {
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "hidden") {
          void this.flushQueuedEvents("hidden");
        }
      });
    }
  }

  private flushQueuedEvents(reason: FlushReason): Promise<TrackResult> {
    if (!this._queue.length) return Promise.resolve({ accepted: 0 });
    if (!this.ensureInitialized()) return Promise.resolve({ accepted: 0, buffered: true });
    if (this._flushPromise) return this._flushPromise;

    this._flushPromise = this.drainQueuedEvents(reason).finally(() => {
      this._flushPromise = null;
      if (this._queue.length && !this._retryTimer && !this._closed) this.scheduleFlush();
    });
    return this._flushPromise;
  }

  private async drainQueuedEvents(reason: FlushReason): Promise<TrackResult> {
    if (!this._queue.length) return { accepted: 0 };

    this.clearFlushTimer();
    this.clearRetryTimer();

    let totalAccepted = 0;
    let sendReason = reason;
    while (this._queue.length) {
      const batch = this._queue.splice(0, Math.min(BATCH_MAX, this._queue.length));
      const outcome = await this.sendTrackBatch(batch, sendReason);

      if (outcome.ok) {
        totalAccepted += outcome.accepted;
        this._retryCount = 0;
        sendReason = "batch";
        continue;
      }

      if (!outcome.retryable) {
        this._retryCount = 0;
        continue;
      }

      // Put failed batch back at the front and retry with backoff.
      this._queue = batch.concat(this._queue);
      this._retryCount++;
      if (this._retryCount > RETRY_MAX) {
        this._queue.splice(0, batch.length);
        this._retryCount = 0;
        continue;
      }
      this.scheduleRetry(outcome.retryAfterMs);
      break;
    }

    return { accepted: totalAccepted };
  }

  private async sendTrackBatch(
    events: TrackEvent[],
    reason: FlushReason,
  ): Promise<{ ok: boolean; retryable: boolean; accepted: number; retryAfterMs: number }> {
    try {
      const useKeepalive = reason === "hidden" || reason === "pagehide";
      const result = await this.post(
        "/track",
        isBrowserEnv() ? { events, clientOriginated: true } : { events },
        { keepalive: isBrowserEnv() && useKeepalive },
      );
      return {
        ok: true,
        retryable: false,
        accepted: this.acceptedFromTrackResponse(result, events.length),
        retryAfterMs: 0,
      };
    } catch (err) {
      if (err instanceof WireLogError) {
        if (!isBrowserEnv()) this.reportError(err);
        return {
          ok: false,
          retryable: this.isRetryableStatus(err.status),
          accepted: 0,
          retryAfterMs: err.retryAfterMs,
        };
      }
      if (!isBrowserEnv()) this.reportError(err instanceof Error ? err : new Error(String(err)));
      return {
        ok: false,
        retryable: true,
        accepted: 0,
        retryAfterMs: 0,
      };
    }
  }

  private isRetryableStatus(status: number): boolean {
    return status === 429 || (status >= 500 && status < 600) || status === 0;
  }

  private acceptedFromTrackResponse(result: unknown, fallback: number): number {
    if (result && typeof result === "object" && "accepted" in result) {
      const accepted = (result as { accepted?: unknown }).accepted;
      if (typeof accepted === "number" && Number.isFinite(accepted)) return accepted;
    }
    return fallback;
  }

  private reportError(err: Error): void {
    if (this._onError) {
      try {
        this._onError(err);
      } catch {
        // never let error callback break the client
      }
    }
  }

  private enrichEvent(event: TrackEvent): TrackEvent {
    const identity = this.browserIdentity();
    const props = this.mergeBrowserContext(event.event_properties);

    return {
      ...identity,
      ...event,
      event_properties: props,
      insert_id: event.insert_id ?? uuid(),
      time: event.time ?? new Date().toISOString(),
      clientOriginated: isBrowserEnv() ? true : event.clientOriginated,
    };
  }

  /**
   * Returns identity fields to merge into events when running in a browser.
   * In Node this returns an empty object so explicit caller values are used as-is.
   *
   * Session and device state are always re-read from web storage so that
   * this client and wirelog.js (the script-tag SDK) stay in lock-step even
   * when one side calls reset() or rotates the session.
   */
  private browserIdentity(): Partial<TrackEvent> {
    if (!isBrowserEnv()) return {};

    this.captureAttribution();

    // Re-read device ID from localStorage in case wirelog.js changed it
    // (e.g. via reset). If storage is empty and we have no in-memory
    // value, generate one and persist so wirelog.js can find it.
    const storedDid = lsGet("wl_did");
    if (storedDid) {
      this._deviceId = storedDid;
    } else if (!this._deviceId) {
      this._deviceId = hexId();
      lsSet("wl_did", this._deviceId);
    }

    // Session management: hydrate from sessionStorage (shared with
    // wirelog.js), rotate on timeout, persist back.  Mirrors the
    // hydrateSession → getSessionId → persistSession flow in wirelog.js.
    const now = Date.now();
    if (!this._sessionId) {
      const storedSid = ssGet(SESSION_ID_KEY);
      const rawLast = ssGet(SESSION_LAST_KEY);
      const storedLast = rawLast ? parseInt(rawLast, 10) : 0;
      if (storedSid && storedLast && !isNaN(storedLast) && (now - storedLast) <= SESSION_TIMEOUT) {
        this._sessionId = storedSid;
        this._lastActivity = storedLast;
      }
    }
    if (!this._sessionId || !this._lastActivity || (now - this._lastActivity) > SESSION_TIMEOUT) {
      this._sessionId = hexId();
    }
    this._lastActivity = now;
    ssSet(SESSION_ID_KEY, this._sessionId);
    ssSet(SESSION_LAST_KEY, String(this._lastActivity));

    // Re-read userId from localStorage in case wirelog.js updated it.
    const storedUid = lsGet("wl_uid");
    if (storedUid && storedUid !== this._userId) {
      this._userId = storedUid;
    }

    return {
      device_id: this._deviceId ?? undefined,
      session_id: this._sessionId,
      user_id: this._userId ?? undefined,
    };
  }

  private mergeBrowserContext(
    props?: Record<string, unknown>,
  ): Record<string, unknown> | undefined {
    if (!isBrowserEnv()) return props;

    const nav = typeof globalThis.navigator === "object" ? globalThis.navigator : undefined;
    const autoProps: Record<string, unknown> = {
      url: window.location.href,
    };
    if (nav?.language) autoProps.language = nav.language;
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tz) autoProps.timezone = tz;
    } catch {
      // Ignore Intl failures.
    }

    return {
      ...autoProps,
      ...(props || {}),
    };
  }

  private captureAttribution(): { first: Record<string, string>; last: Record<string, string> } {
    if (!isBrowserEnv()) return { first: {}, last: {} };

    const current = extractAttributionFromLocation();
    let first = readSessionJSON(ATTR_FIRST_KEY);
    let last = readSessionJSON(ATTR_LAST_KEY);

    if (hasOwnKeys(current)) {
      if (!hasOwnKeys(first)) {
        first = current;
        writeSessionJSON(ATTR_FIRST_KEY, first);
      }
      last = current;
      writeSessionJSON(ATTR_LAST_KEY, last);
    }

    return { first, last };
  }

  private async post(
    path: string,
    body: unknown,
    opts?: { keepalive?: boolean },
  ): Promise<unknown> {
    if (!this._initialized) {
      console.warn("wirelog: call wl.init({ apiKey }) before tracking events");
      return {};
    }
    const url = `${this.host}${path}`;
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": this.apiKey,
      },
      body: JSON.stringify(body),
      keepalive: opts?.keepalive ?? false,
    });

    if (!resp.ok) {
      const text = await resp.text();
      const retryAfterMs = parseRetryAfterMs(resp.headers.get("Retry-After"));
      throw new WireLogError(resp.status, text, retryAfterMs);
    }

    const contentType = resp.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      return resp.json();
    }
    return resp.text();
  }
}

/** Module-level singleton. Call `wl.init({ apiKey })` once, then use everywhere. */
export const wl = new WireLog();
