/**
 * Tests for the per-instance rate limiter and Retry-After parsing.
 */

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  RateLimiter,
  WindowCounter,
  parseRetryAfterMs,
  rateLimitStatsTotal,
  type DropReason,
} from "./ratelimit.js";
import {
  PayloadTooLargeError,
  RateLimitedError,
  WireLog,
  WireLogError,
} from "./client.js";

// -- Fake clock --

class FakeClock {
  private nowMs: number;
  constructor(start = 1_700_000_000_000) {
    this.nowMs = start;
  }
  now = (): number => this.nowMs;
  advance(ms: number): void {
    this.nowMs += ms;
  }
}

// -- WindowCounter --

describe("WindowCounter", () => {
  it("empty total is zero", () => {
    const w = new WindowCounter(60_000, 6);
    assert.equal(w.total(0), 0);
  });

  it("adds and counts", () => {
    const w = new WindowCounter(60_000, 6);
    for (let i = 0; i < 5; i++) w.add(1_000_000);
    assert.equal(w.total(1_000_000), 5);
  });

  it("evicts old buckets", () => {
    const w = new WindowCounter(60_000, 6); // 6 x 10s buckets
    w.add(1_000_000);
    w.add(1_000_000);
    w.add(1_000_000 + 65_000); // 65s later — original outside window
    assert.equal(w.total(1_000_000 + 65_000), 1);
  });

  it("distributes across buckets", () => {
    const w = new WindowCounter(60_000, 6);
    for (let i = 0; i < 6; i++) w.add(1_000_000 + i * 10_000);
    assert.equal(w.total(1_000_000 + 55_000), 6);
  });
});

// -- RateLimiter token bucket (L1) --

describe("RateLimiter token bucket", () => {
  it("allows burst up to capacity", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1,
        burst: 10,
        eventsPerMinute: 1000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      clock.now,
    );
    for (let i = 0; i < 10; i++) {
      assert.equal(r.allow(), "ok", `event ${i}`);
    }
    assert.equal(r.allow(), "burst");
  });

  it("refills over time", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1,
        burst: 5,
        eventsPerMinute: 1000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      clock.now,
    );
    for (let i = 0; i < 5; i++) r.allow();
    assert.equal(r.allow(), "burst");
    clock.advance(3000);
    for (let i = 0; i < 3; i++) assert.equal(r.allow(), "ok");
    assert.equal(r.allow(), "burst");
  });

  it("refill caps at burst", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1,
        burst: 3,
        eventsPerMinute: 1000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      clock.now,
    );
    clock.advance(100_000);
    for (let i = 0; i < 3; i++) assert.equal(r.allow(), "ok");
    assert.equal(r.allow(), "burst");
  });
});

// -- RateLimiter sustained windows (L2) --

describe("RateLimiter sustained windows", () => {
  it("enforces per-minute", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1000,
        burst: 1000,
        eventsPerMinute: 5,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      clock.now,
    );
    for (let i = 0; i < 5; i++) assert.equal(r.allow(), "ok");
    assert.equal(r.allow(), "per_minute");
  });

  it("per-minute recovers after window", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1000,
        burst: 1000,
        eventsPerMinute: 3,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      clock.now,
    );
    for (let i = 0; i < 3; i++) r.allow();
    assert.equal(r.allow(), "per_minute");
    clock.advance(61_000);
    assert.equal(r.allow(), "ok");
  });

  it("enforces per-hour", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1000,
        burst: 1000,
        eventsPerMinute: 1000,
        eventsPerHour: 10,
        eventsPerDay: 1_000_000,
      },
      clock.now,
    );
    for (let i = 0; i < 10; i++) assert.equal(r.allow(), "ok");
    assert.equal(r.allow(), "per_hour");
  });

  it("enforces per-day", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1000,
        burst: 1000,
        eventsPerMinute: 1000,
        eventsPerHour: 1000,
        eventsPerDay: 7,
      },
      clock.now,
    );
    for (let i = 0; i < 7; i++) {
      clock.advance(3_600_000);
      assert.equal(r.allow(), "ok");
    }
    assert.equal(r.allow(), "per_day");
  });
});

describe("RateLimiter sustained drip", () => {
  it("catches one-per-second leak over two hours", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1,
        burst: 10,
        eventsPerMinute: 60,
        eventsPerHour: 1000,
        eventsPerDay: 10000,
      },
      clock.now,
    );
    let allowed = 0;
    let dropped = 0;
    for (let i = 0; i < 7200; i++) {
      clock.advance(1000);
      const r1: DropReason = r.allow();
      if (r1 === "ok") allowed++;
      else dropped++;
    }
    assert.ok(allowed < 2200, `allowed=${allowed}`);
    assert.ok(dropped > 5000, `dropped=${dropped}`);
  });
});

describe("RateLimiter disabled", () => {
  it("allows everything", () => {
    const r = new RateLimiter({ disabled: true });
    for (let i = 0; i < 100_000; i++) {
      assert.equal(r.allow(), "ok");
    }
    assert.equal(rateLimitStatsTotal(r.stats()), 0);
  });
});

describe("RateLimiter stats", () => {
  it("counts by reason", () => {
    const clock = new FakeClock();
    const r = new RateLimiter(
      {
        eventsPerSecond: 1,
        burst: 2,
        eventsPerMinute: 5,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      clock.now,
    );
    for (let i = 0; i < 5; i++) r.allow();
    assert.equal(r.stats().droppedBurst, 3);
    clock.advance(5000);
    for (let i = 0; i < 3; i++) r.allow();
    clock.advance(5000);
    for (let i = 0; i < 3; i++) r.allow();
    assert.ok(r.stats().droppedPerMinute > 0);
    r.recordPayloadDrop();
    r.recordPayloadDrop();
    assert.equal(r.stats().droppedPayloadSize, 2);
  });
});

// -- parseRetryAfterMs --

describe("parseRetryAfterMs", () => {
  it("parses seconds", () => {
    assert.equal(parseRetryAfterMs("5"), 5000);
  });
  it("returns 0 on empty/null", () => {
    assert.equal(parseRetryAfterMs(""), 0);
    assert.equal(parseRetryAfterMs(null), 0);
    assert.equal(parseRetryAfterMs(undefined), 0);
    assert.equal(parseRetryAfterMs("   "), 0);
  });
  it("returns 0 on negative or zero", () => {
    assert.equal(parseRetryAfterMs("-5"), 0);
    assert.equal(parseRetryAfterMs("0"), 0);
  });
  it("parses HTTP-date in the future", () => {
    const nowMs = 1_700_000_000_000;
    const future = new Date(nowMs + 30_000).toUTCString();
    const got = parseRetryAfterMs(future, nowMs);
    assert.ok(got > 28_000 && got < 32_000, `got=${got}`);
  });
  it("returns 0 for past HTTP-date", () => {
    const nowMs = 1_700_000_000_000;
    const past = new Date(nowMs - 30_000).toUTCString();
    assert.equal(parseRetryAfterMs(past, nowMs), 0);
  });
  it("returns 0 on garbage", () => {
    assert.equal(parseRetryAfterMs("not a date"), 0);
  });
});

// -- WireLog client integration --

let lastRequest: { path: string; body: Record<string, unknown> } | null = null;
let requestCount = 0;
let mockResponse: { body: string; status: number; headers: Record<string, string> } = {
  body: '{"accepted":1}',
  status: 200,
  headers: {},
};

const server = http.createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => {
    requestCount++;
    const bodyStr = Buffer.concat(chunks).toString();
    lastRequest = {
      path: req.url ?? "",
      body: bodyStr ? JSON.parse(bodyStr) : {},
    };
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...mockResponse.headers,
    };
    res.writeHead(mockResponse.status, headers);
    res.end(mockResponse.body);
  });
});

let baseUrl = "";

before(async () => {
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

after(() => {
  server.close();
});

beforeEach(() => {
  lastRequest = null;
  requestCount = 0;
  mockResponse = { body: '{"accepted":1}', status: 200, headers: {} };
});

describe("WireLog client + rate limiter", () => {
  it("track honours burst limit", async () => {
    const clock = new FakeClock();
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: {
        eventsPerSecond: 1,
        burst: 5,
        eventsPerMinute: 1000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      _now: clock.now,
    });
    for (let i = 0; i < 100; i++) {
      await wl.track({ event_type: "spam" });
    }
    const stats = wl.rateLimitStats();
    assert.equal(stats.droppedBurst, 95);
    await wl.close();
  });

  it("track rejects oversized payload", async () => {
    const errors: Error[] = [];
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: {
        eventsPerSecond: 1000,
        burst: 1000,
        eventsPerMinute: 1_000_000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
        maxEventBytes: 200,
      },
      onError: (e) => errors.push(e),
    });
    await wl.track({ event_type: "small" });
    await wl.track({
      event_type: "big",
      event_properties: { blob: "x".repeat(1000) },
    });
    const tooLarge = errors.filter((e) => e instanceof PayloadTooLargeError);
    assert.equal(tooLarge.length, 1);
    assert.equal(wl.rateLimitStats().droppedPayloadSize, 1);
    await wl.close();
  });

  it("disabled rate limit passes all events", async () => {
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: { disabled: true },
    });
    for (let i = 0; i < 100; i++) await wl.track({ event_type: "test" });
    assert.equal(rateLimitStatsTotal(wl.rateLimitStats()), 0);
    await wl.close();
  });

  it("default rate limit is active", async () => {
    const errors: Error[] = [];
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      onError: (e) => errors.push(e),
    });
    for (let i = 0; i < 100; i++) await wl.track({ event_type: "flood" });
    const rateDrops = errors.filter((e) => e instanceof RateLimitedError);
    assert.ok(rateDrops.length >= 80, `rateDrops=${rateDrops.length}`);
    assert.equal(wl.rateLimitStats().droppedBurst, rateDrops.length);
    await wl.close();
  });

  it("identify honours burst limit", async () => {
    mockResponse = {
      body: JSON.stringify({ ok: true }),
      status: 200,
      headers: {},
    };
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: {
        eventsPerSecond: 1,
        burst: 3,
        eventsPerMinute: 1000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
    });
    for (let i = 0; i < 3; i++) {
      await wl.identify({ user_id: "u" });
    }
    await assert.rejects(
      async () => wl.identify({ user_id: "u" }),
      (err: unknown) => err instanceof RateLimitedError,
    );
    assert.equal(wl.rateLimitStats().droppedBurst, 1);
    await wl.close();
  });

  it("init() applies rateLimit override on the singleton path", async () => {
    const wl = new WireLog();
    wl.init({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: {
        eventsPerSecond: 1,
        burst: 3,
        eventsPerMinute: 1000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
    });
    for (let i = 0; i < 5; i++) await wl.track({ event_type: "t" });
    assert.equal(wl.rateLimitStats().droppedBurst, 2);
    await wl.close();
  });

  it("init({ rateLimit: { disabled: true } }) actually disables the limiter", async () => {
    const wl = new WireLog();
    wl.init({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: { disabled: true },
    });
    for (let i = 0; i < 100; i++) await wl.track({ event_type: "t" });
    assert.equal(rateLimitStatsTotal(wl.rateLimitStats()), 0);
    await wl.close();
  });

  it("track() drops unserializable payloads (circular ref)", async () => {
    const errors: Error[] = [];
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: {
        eventsPerSecond: 1000,
        burst: 1000,
        eventsPerMinute: 1_000_000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      onError: (e) => errors.push(e),
    });
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    await wl.track({ event_type: "broken", event_properties: { c: circular } });
    const drops = errors.filter((e) => e instanceof PayloadTooLargeError);
    assert.equal(drops.length, 1);
    assert.equal(wl.rateLimitStats().droppedPayloadSize, 1);
    // Nothing should have been queued or sent.
    assert.equal(requestCount, 0);
    await wl.close();
  });

  it("track() drops unserializable payloads (BigInt)", async () => {
    const errors: Error[] = [];
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: {
        eventsPerSecond: 1000,
        burst: 1000,
        eventsPerMinute: 1_000_000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      onError: (e) => errors.push(e),
    });
    await wl.track({
      event_type: "broken",
      event_properties: { big: BigInt(123) as unknown as number },
    });
    const drops = errors.filter((e) => e instanceof PayloadTooLargeError);
    assert.equal(drops.length, 1);
    assert.equal(wl.rateLimitStats().droppedPayloadSize, 1);
    await wl.close();
  });

  it("trackBatch is a no-op when disabled or closed", async () => {
    const wl = new WireLog({ apiKey: "sk_test", host: baseUrl, disabled: true });
    const r = await wl.trackBatch([{ event_type: "x" }, { event_type: "y" }]);
    assert.equal(r.accepted, 0);
    assert.equal(requestCount, 0);
    await wl.close();
  });

  it("trackBatch rejects batches over 2000 events", async () => {
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: { disabled: true },
    });
    const events = Array.from({ length: 2001 }, () => ({ event_type: "x" }));
    await assert.rejects(async () => wl.trackBatch(events));
    assert.equal(requestCount, 0);
    await wl.close();
  });

  it("trackBatch drops oversize events from the batch", async () => {
    const errors: Error[] = [];
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: {
        eventsPerSecond: 1000,
        burst: 1000,
        eventsPerMinute: 1_000_000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
        maxEventBytes: 200,
      },
      onError: (e) => errors.push(e),
    });
    const result = await wl.trackBatch([
      { event_type: "small_a" },
      { event_type: "big", event_properties: { blob: "x".repeat(500) } },
      { event_type: "small_b" },
    ]);
    assert.ok(result.accepted >= 0);
    const tooLarge = errors.filter((e) => e instanceof PayloadTooLargeError);
    assert.equal(tooLarge.length, 1);
    assert.equal(wl.rateLimitStats().droppedPayloadSize, 1);
    // Server should have received the 2 surviving events.
    assert.equal(requestCount, 1);
    const sent = lastRequest?.body.events as Array<{ event_type: string }>;
    assert.equal(sent.length, 2);
    await wl.close();
  });

  it("trackBatch drops events past the burst capacity", async () => {
    const errors: Error[] = [];
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: {
        eventsPerSecond: 1,
        burst: 5,
        eventsPerMinute: 1000,
        eventsPerHour: 1_000_000,
        eventsPerDay: 1_000_000,
      },
      onError: (e) => errors.push(e),
    });
    const events = Array.from({ length: 20 }, () => ({ event_type: "e" }));
    await wl.trackBatch(events);
    const rateDrops = errors.filter((e) => e instanceof RateLimitedError);
    assert.equal(rateDrops.length, 15);
    assert.equal(wl.rateLimitStats().droppedBurst, 15);
    assert.equal(requestCount, 1);
    const sent = lastRequest?.body.events as Array<{ event_type: string }>;
    assert.equal(sent.length, 5);
    await wl.close();
  });

  it("trackBatch with disabled limiter passes everything", async () => {
    const wl = new WireLog({
      apiKey: "sk_test",
      host: baseUrl,
      rateLimit: { disabled: true },
    });
    const events = Array.from({ length: 50 }, () => ({ event_type: "e" }));
    await wl.trackBatch(events);
    assert.equal(rateLimitStatsTotal(wl.rateLimitStats()), 0);
    assert.equal(requestCount, 1);
    const sent = lastRequest?.body.events as Array<{ event_type: string }>;
    assert.equal(sent.length, 50);
    await wl.close();
  });

  it("WireLogError exposes Retry-After ms", async () => {
    mockResponse = {
      body: '{"error":"slow down"}',
      status: 429,
      headers: { "Retry-After": "7" },
    };
    const wl = new WireLog({ apiKey: "sk_test", host: baseUrl });
    await assert.rejects(
      async () => wl.query("* | count"),
      (err: unknown) => {
        if (!(err instanceof WireLogError)) return false;
        return err.status === 429 && err.retryAfterMs === 7000;
      },
    );
    await wl.close();
  });
});
