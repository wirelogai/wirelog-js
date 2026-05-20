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
const ASSIGNMENT_BUCKET_COUNT = 100000;

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

function utf8Bytes(input: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < input.length; i++) {
    let code = input.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < input.length) {
      const next = input.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i++;
      }
    }
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return out;
}

function sha256Hex(input: string): string {
  function rightRotate(value: number, amount: number): number {
    return (value >>> amount) | (value << (32 - amount));
  }

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const bytes = utf8Bytes(input);
  const words: number[] = [];
  const bitLength = bytes.length * 8;
  const initialHash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  for (let i = 0; i < bytes.length; i++) {
    words[i >> 2] = (words[i >> 2] ?? 0) | (bytes[i] << (((3 - i) % 4) * 8));
  }
  words[words.length] = Math.floor(bitLength / maxWord);
  words[words.length] = bitLength;

  let hash = initialHash.slice();
  for (let offset = 0; offset < words.length;) {
    const w = words.slice(offset, offset += 16);
    const oldHash = hash.slice();
    for (let round = 0; round < 64; round++) {
      const w15 = w[round - 15];
      const w2 = w[round - 2];
      const a = hash[0];
      const e = hash[4];
      const temp1 = hash[7]
        + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
        + ((e & hash[5]) ^ ((~e) & hash[6]))
        + k[round]
        + (w[round] = round < 16 ? (w[round] ?? 0) : (
          (w[round - 16] ?? 0)
          + (rightRotate(w15 ?? 0, 7) ^ rightRotate(w15 ?? 0, 18) ^ ((w15 ?? 0) >>> 3))
          + (w[round - 7] ?? 0)
          + (rightRotate(w2 ?? 0, 17) ^ rightRotate(w2 ?? 0, 19) ^ ((w2 ?? 0) >>> 10))
        ) | 0);
      const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
  }

  let result = "";
  for (let i = 0; i < 8; i++) {
    for (let j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? "0" : "") + b.toString(16);
    }
  }
  return result;
}

function hashInput(parts: Array<string | number>): string {
  return parts.map((part) => String(part)).join("\x1f");
}

function hashBucket(projectId: string, environment: string, entityKey: string, salt: string, subjectKey: string): number {
  const hex = sha256Hex(hashInput([projectId, environment, entityKey, salt, subjectKey]));
  const first64 = BigInt(`0x${hex.slice(0, 16)}`);
  const first53 = first64 >> 11n;
  const bucket = Number((first53 * BigInt(ASSIGNMENT_BUCKET_COUNT)) / (1n << 53n));
  return Math.min(bucket, ASSIGNMENT_BUCKET_COUNT - 1);
}

function subjectHash(subjectKey: string): string {
  return `sha256:${sha256Hex(subjectKey)}`;
}

function choiceAssignmentId(projectId: string, environment: string, choiceKey: string, version: string, subjectKey: string): string {
  return `chas_${sha256Hex(hashInput([projectId, environment, choiceKey, version, subjectKey])).slice(0, 32)}`;
}

/** @internal */
export const __wirelogInternals = { hashBucket, subjectHash, choiceAssignmentId };

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
  /** Environment label attached to choice exposures. Defaults to production. */
  environment?: string;
  /** Stable seed used for choice assignment. Defaults to apiKey. Set to a project ID to survive key rotation. */
  choiceSeed?: string;
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

export interface Subject {
  attributes?: Record<string, unknown>;
  user_id?: string;
  device_id?: string;
  account_id?: string;
  org_id?: string;
  session_id?: string;
  thread_id?: string;
  request_id?: string;
  custom_key?: string;
  [key: string]: unknown;
}

export interface Assignment {
  value?: unknown;
  choice_key?: string;
  choice_version?: string;
  environment_key?: string;
  variant_weight?: number;
  variant_key?: string;
  reason: string;
  assignment_id?: string;
  allocation_key?: string;
  randomization_unit?: string;
  subject_key_hash?: string;
  exposure_allowed: boolean;
}

export interface ChoiceVariant<T = unknown> {
  key?: string;
  value?: T;
  payload?: T;
  weight?: number;
}

export interface ChoiceOptions {
  subject?: Subject;
  unit?: string;
  seed?: string;
  choiceSeed?: string;
  version?: string | number;
  salt?: string;
  weights?: number[];
  allocation?: number;
  fallback?: unknown;
  expose?: boolean;
  environment?: string;
}

export interface SDKStats {
  exposureCount: number;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function subjectValue(subject: Subject, unit: string): string {
  const aliases: Record<string, string> = {
    user: "user_id",
    device: "device_id",
    account: "account_id",
    org: "org_id",
    session: "session_id",
    thread: "thread_id",
    request: "request_id",
    custom: "custom_key",
  };
  const key = aliases[unit] ?? unit;
  if (key.startsWith("attr.")) return stringValue(subject.attributes?.[key.slice(5)]);
  return stringValue(subject[key]);
}

function pickVariant(variants: unknown, bucket: number): Record<string, unknown> | null {
  if (!Array.isArray(variants) || variants.length === 0) return null;
  let total = 0;
  for (const variant of variants) {
    if (variant && typeof variant === "object") {
      total += Math.max(0, Number((variant as Record<string, unknown>).weight || 0));
    }
  }
  if (total <= 0) return null;
  const point = (bucket / ASSIGNMENT_BUCKET_COUNT) * total;
  let cursor = 0;
  for (const variant of variants) {
    if (!variant || typeof variant !== "object") continue;
    const record = variant as Record<string, unknown>;
    cursor += Math.max(0, Number(record.weight || 0));
    if (point < cursor) return record;
  }
  const last = variants[variants.length - 1];
  return last && typeof last === "object" ? last as Record<string, unknown> : null;
}

interface NormalizedChoiceVariant {
  key: string;
  value: unknown;
  weight: number;
}

function choiceVariantKey(value: unknown, index: number): string {
  if (typeof value === "string" && value) return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return `v${index + 1}`;
}

function normalizeChoiceVariants(rawVariants: unknown[], options: ChoiceOptions): NormalizedChoiceVariant[] {
  return rawVariants.map((raw, index) => {
    let value = raw;
    let key = "";
    let weight = Number(options.weights?.[index] || 0);
    if (
      raw
      && typeof raw === "object"
      && !Array.isArray(raw)
      && (
        Object.prototype.hasOwnProperty.call(raw, "value")
        || Object.prototype.hasOwnProperty.call(raw, "payload")
        || Object.prototype.hasOwnProperty.call(raw, "key")
        || Object.prototype.hasOwnProperty.call(raw, "weight")
      )
    ) {
      const record = raw as Record<string, unknown>;
      value = Object.prototype.hasOwnProperty.call(record, "value") ? record.value : record.payload;
      key = stringValue(record.key) || choiceVariantKey(value, index);
      if (!weight) weight = Number(record.weight || 0);
    } else {
      key = choiceVariantKey(value, index);
    }
    if (!weight) weight = 1;
    return { key, value, weight };
  });
}

function choiceVersion(variants: NormalizedChoiceVariant[], explicit: ChoiceOptions["version"], salt: string): string {
  if (explicit !== undefined && explicit !== null && explicit !== "") return String(explicit);
  try {
    return sha256Hex(JSON.stringify(stableChoiceSchema(variants, salt))).slice(0, 12);
  } catch {
    return sha256Hex(String(variants.length)).slice(0, 12);
  }
}

function stableChoiceSchema(variants: NormalizedChoiceVariant[], salt: string): { salt: string; variants: Array<{ key: string; weight: number }> } {
  return {
    salt,
    variants: variants.map((variant) => ({ key: variant.key, weight: variant.weight })),
  };
}

function inAllocation(bucket: number, allocationPercent: number): boolean {
  if (allocationPercent >= 100) return true;
  if (allocationPercent <= 0) return false;
  return bucket < Math.round((allocationPercent / 100) * ASSIGNMENT_BUCKET_COUNT);
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
  private _choiceSeed: string;
  private host: string;
  private _environment: string;
  private _initialized = false;
  private _disabled: boolean;
  private _onError: ((err: Error) => void) | undefined;

  // Browser identity state — populated only when running in a browser.
  private _deviceId: string | null = null;
  private _sessionId: string | null = null;
  private _lastActivity = 0;
  private _userId: string | null = null;
  private _choiceSubjectUnit: string | null = null;
  private _choiceUnits = new Map<string, string>();
  private _choiceUnitWarnings = new Set<string>();

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
  private _sdkStats: SDKStats = {
    exposureCount: 0,
  };

  constructor(config: WireLogConfig = {}) {
    this.apiKey = config.apiKey ?? envVar("WIRELOG_API_KEY") ?? "";
    this._choiceSeed = config.choiceSeed ?? envVar("WIRELOG_CHOICE_SEED") ?? this.apiKey;
    this.host = (config.host ?? envVar("WIRELOG_HOST") ?? "https://api.wirelog.ai").replace(/\/$/, "");
    this._environment = config.environment ?? "production";
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
    if (config.choiceSeed) this._choiceSeed = config.choiceSeed;
    else if (!this._choiceSeed && this.apiKey) this._choiceSeed = this.apiKey;
    if (config.host) this.host = config.host.replace(/\/$/, "");
    if (config.environment) this._environment = config.environment;
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

  /** Explicitly use the current anonymous visitor as the assignment unit for choice(). */
  visitor(): string {
    if (!this._deviceId) {
      this._deviceId = hexId();
      lsSet("wl_did", this._deviceId);
    }
    this._choiceSubjectUnit = "device_id";
    return this._deviceId;
  }

  /** Resolve a local choice and return only the selected value. */
  choice<T = unknown>(choiceKey: string, variants: Array<T | ChoiceVariant<T>>, opts: ChoiceOptions = {}): T {
    return this.assignment<T>(choiceKey, variants, opts).value as T;
  }

  /** Resolve a local choice and return the full assignment packet. */
  assignment<T = unknown>(choiceKey: string, variants: Array<T | ChoiceVariant<T>>, opts: ChoiceOptions = {}): Assignment {
    return this.evaluateChoice(choiceKey, variants, opts);
  }

  /** Async convenience wrapper for callers that prefer promise-style choice flows. */
  async choiceAsync<T = unknown>(choiceKey: string, variants: Array<T | ChoiceVariant<T>>, opts: ChoiceOptions = {}): Promise<T> {
    return this.choice<T>(choiceKey, variants, opts);
  }

  /** Log an explicit choice exposure through the existing event queue. */
  async expose(assignment: Assignment, subject: Subject = {}): Promise<boolean> {
    if (!assignment.exposure_allowed || !assignment.choice_key) return false;
    const previousUser = this._userId;
    if (typeof subject.user_id === "string" && subject.user_id) this._userId = subject.user_id;
    const event: TrackEvent = {
      event_type: "wirelog.exposure",
      event_properties: this.exposureProps(assignment),
      insert_id: assignment.assignment_id || undefined,
    };
    if (subject.user_id) event.user_id = stringValue(subject.user_id);
    if (subject.device_id) event.device_id = stringValue(subject.device_id);
    if (subject.session_id) event.session_id = stringValue(subject.session_id);
    if (!event.user_id && assignment.randomization_unit === "user_id" && this._userId) event.user_id = this._userId;
    if (!event.device_id && assignment.randomization_unit === "device_id" && this._deviceId) event.device_id = this._deviceId;
    if (!event.session_id && assignment.randomization_unit === "session_id" && this._sessionId) event.session_id = this._sessionId;
    await this.track(event);
    this._userId = previousUser;
    this._sdkStats.exposureCount++;
    return true;
  }

  /** Snapshot of choice exposure counters. */
  choiceStats(): SDKStats {
    return { ...this._sdkStats };
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

    this._userId = userID;
    this._choiceSubjectUnit = "user_id";

    let mergedOps = params.user_property_ops;
    let shouldMarkAttrSynced = false;

    if (isBrowserEnv()) {
      // Re-read device ID from localStorage in case wirelog.js changed it.
      const storedDid = lsGet("wl_did");
      if (storedDid) this._deviceId = storedDid;

      this._choiceSubjectUnit = "user_id";
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
    this._choiceSubjectUnit = null;
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

  private evaluateChoice<T>(choiceKey: string, rawVariants: Array<T | ChoiceVariant<T>>, opts: ChoiceOptions): Assignment {
    const variants = normalizeChoiceVariants(rawVariants as unknown[], opts);
    const fallback = Object.prototype.hasOwnProperty.call(opts, "fallback")
      ? opts.fallback
      : variants[0]?.value;
    if (!choiceKey || variants.length === 0) {
      return {
        choice_key: choiceKey,
        value: fallback,
        reason: "invalid_choice",
        exposure_allowed: false,
      };
    }
    const subject = opts.subject || {};
    const resolved = this.resolveChoiceSubject(subject, opts.unit);
    if (!resolved?.key) {
      throw new Error("wirelog.choice requires wirelog.identify(userId), wirelog.visitor(), or an explicit subject before assignment");
    }
    this.warnChoiceUnitChange(choiceKey, resolved.unit);

    const environment = opts.environment || this._environment;
    const projectId = opts.seed || opts.choiceSeed || this._choiceSeed || this.apiKey;
    const salt = opts.salt || choiceKey;
    const version = choiceVersion(variants, opts.version, salt);
    const allocation = Number(opts.allocation ?? 100);
    const allocationBucket = hashBucket(projectId, environment, choiceKey, `${salt}:allocation`, resolved.key);
    if (!inAllocation(allocationBucket, Number.isFinite(allocation) ? allocation : 100)) {
      return {
        choice_key: choiceKey,
        value: fallback,
        reason: "not_allocated",
        choice_version: version,
        environment_key: environment,
        allocation_key: choiceKey,
        randomization_unit: resolved.unit,
        subject_key_hash: subjectHash(resolved.key),
        exposure_allowed: false,
      };
    }

    const selected = pickVariant(variants, hashBucket(projectId, environment, choiceKey, `${salt}:variant`, resolved.key)) as
      | NormalizedChoiceVariant
      | null;
    if (!selected) {
      return {
        choice_key: choiceKey,
        value: fallback,
        reason: "default",
        choice_version: version,
        environment_key: environment,
        allocation_key: choiceKey,
        randomization_unit: resolved.unit,
        subject_key_hash: subjectHash(resolved.key),
        exposure_allowed: false,
      };
    }

    const assignment: Assignment = {
      choice_key: choiceKey,
      value: selected.value,
      variant_key: selected.key,
      variant_weight: selected.weight,
      reason: "client_choice",
      choice_version: version,
      environment_key: environment,
      assignment_id: choiceAssignmentId(projectId, environment, choiceKey, version, resolved.key),
      allocation_key: choiceKey,
      randomization_unit: resolved.unit,
      subject_key_hash: subjectHash(resolved.key),
      exposure_allowed: true,
    };
    if (opts.expose !== false) void this.expose(assignment, subject);
    return assignment;
  }

  private resolveChoiceSubject(subject: Subject, requestedUnit?: string): { unit: string; key: string } | null {
    if (requestedUnit) return { unit: requestedUnit, key: this.choiceSubjectValue(subject, requestedUnit) };
    if (subject.user_id) return { unit: "user_id", key: stringValue(subject.user_id) };
    if (subject.device_id) return { unit: "device_id", key: stringValue(subject.device_id) };
    if (subject.account_id) return { unit: "account_id", key: stringValue(subject.account_id) };
    if (subject.org_id) return { unit: "org_id", key: stringValue(subject.org_id) };
    if (subject.session_id) return { unit: "session_id", key: stringValue(subject.session_id) };
    if (subject.custom_key) return { unit: "custom_key", key: stringValue(subject.custom_key) };
    if (this._choiceSubjectUnit) {
      return { unit: this._choiceSubjectUnit, key: this.choiceSubjectValue(subject, this._choiceSubjectUnit) };
    }
    return null;
  }

  private choiceSubjectValue(subject: Subject, unit: string): string {
    const explicit = subjectValue(subject, unit);
    if (explicit) return explicit;
    if (unit === "user_id" || unit === "user") return this._userId || "";
    if (unit === "device_id" || unit === "device") return this._deviceId || "";
    return "";
  }

  private warnChoiceUnitChange(choiceKey: string, unit: string): void {
    const previous = this._choiceUnits.get(choiceKey);
    if (!previous) {
      this._choiceUnits.set(choiceKey, unit);
      return;
    }
    if (previous === unit) return;
    const warningKey = `${choiceKey}\x1f${unit}`;
    if (this._choiceUnitWarnings.has(warningKey)) return;
    this._choiceUnitWarnings.add(warningKey);
    console.warn(`wirelog.choice: choice '${choiceKey}' used randomization unit '${previous}' and now '${unit}'. Use a stable unit per choice key to preserve stickiness.`);
  }

  private exposureProps(assignment: Assignment): Record<string, unknown> {
    const value = assignment.value;
    let payloadHash = "";
    if (value !== undefined) {
      try {
        payloadHash = `sha256:${sha256Hex(JSON.stringify(value))}`;
      } catch {
        payloadHash = "";
      }
    }
    return {
      environment_key: assignment.environment_key || this._environment,
      choice_key: assignment.choice_key || "",
      choice_version: assignment.choice_version || "",
      choice_kind: "choice",
      variant_key: assignment.variant_key || "",
      variant_weight: assignment.variant_weight === undefined ? "" : String(assignment.variant_weight),
      randomization_unit: assignment.randomization_unit || "",
      subject_key_hash: assignment.subject_key_hash || "",
      assignment_id: assignment.assignment_id || "",
      allocation_key: assignment.allocation_key || "",
      reason: assignment.reason || "",
      payload_hash: payloadHash,
    };
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
