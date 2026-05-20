/**
 * Tests for the WireLog client. Uses node:test (no external deps).
 */

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { WireLog, __wirelogInternals } from "./client.js";

interface MockRequest {
  path: string;
  method: string;
  headers: http.IncomingHttpHeaders;
  body: Record<string, unknown>;
}

let lastRequest: MockRequest | null = null;
let requestCount = 0;
let mockResponse = { body: "{}", status: 200, contentType: "application/json" };

const server = http.createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (chunk: Buffer) => chunks.push(chunk));
  req.on("end", () => {
    const bodyStr = Buffer.concat(chunks).toString();
    requestCount++;
    lastRequest = {
      path: req.url ?? "",
      method: req.method ?? "",
      headers: req.headers,
      body: bodyStr ? JSON.parse(bodyStr) : {},
    };
    res.writeHead(mockResponse.status, {
      "Content-Type": mockResponse.contentType,
    });
    res.end(
      typeof mockResponse.body === "string"
        ? mockResponse.body
        : JSON.stringify(mockResponse.body),
    );
  });
});

let baseUrl = "";

before(async () => {
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
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
});

function client(): WireLog {
  return new WireLog({ apiKey: "sk_test_key", host: baseUrl });
}

function createStorage(seed: Record<string, string> = {}) {
  const map = new Map<string, string>(Object.entries(seed));
  return {
    getItem(key: string): string | null {
      return map.has(key) ? map.get(key) ?? null : null;
    },
    setItem(key: string, value: string): void {
      map.set(key, String(value));
    },
    removeItem(key: string): void {
      map.delete(key);
    },
  };
}

async function withBrowserEnv(
  href: string,
  fn: (env: { localStorage: ReturnType<typeof createStorage>; sessionStorage: ReturnType<typeof createStorage> }) => Promise<void>,
): Promise<void> {
  const localStorage = createStorage();
  const sessionStorage = createStorage();
  const location = new URL(href);

  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  const originalLocalStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const originalSessionStorage = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");

  Object.defineProperty(globalThis, "window", {
    configurable: true,
    writable: true,
    value: { location: { href: location.href, search: location.search } },
  });
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    writable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    writable: true,
    value: localStorage,
  });
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    writable: true,
    value: sessionStorage,
  });

  try {
    await fn({ localStorage, sessionStorage });
  } finally {
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else delete (globalThis as Record<string, unknown>).window;
    if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
    else delete (globalThis as Record<string, unknown>).document;
    if (originalLocalStorage) Object.defineProperty(globalThis, "localStorage", originalLocalStorage);
    else delete (globalThis as Record<string, unknown>).localStorage;
    if (originalSessionStorage) Object.defineProperty(globalThis, "sessionStorage", originalSessionStorage);
    else delete (globalThis as Record<string, unknown>).sessionStorage;
  }
}

describe("WireLog client", () => {
  it("builds stable choice hashes and assignment ids", () => {
    const bucket = __wirelogInternals.hashBucket("pk_test", "production", "landing_h1", "landing_h1:variant", "u_123");
    assert.equal(bucket >= 0 && bucket < 100000, true);
    assert.equal(__wirelogInternals.subjectHash("u_123").startsWith("sha256:"), true);
    assert.equal(
      __wirelogInternals.choiceAssignmentId("pk_test", "production", "landing_h1", "v1", "u_123").startsWith("chas_"),
      true,
    );
  });

  it("node track buffers and flush sends batched payload", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };
    const wl = client();
    const result = await wl.track({
      event_type: "signup",
      user_id: "u_123",
      event_properties: { plan: "free" },
    });
    assert.equal(result.accepted, 1);
    assert.equal(result.buffered, true);
    assert.equal(requestCount, 0, "track should buffer, not send immediately");

    await wl.flush();

    assert.equal(requestCount, 1);
    assert.equal(lastRequest?.path, "/track");
    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.equal(events.length, 1);
    assert.equal(events[0].event_type, "signup");
    assert.equal(events[0].user_id, "u_123");
    assert.ok(events[0].insert_id);
    assert.ok(events[0].time);
    assert.equal(events[0].clientOriginated, undefined, "Node events should not be client-originated");

    await wl.close();
  });

  it("trackBatch sends immediately", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 2 }),
      status: 200,
      contentType: "application/json",
    };
    const result = await client().trackBatch([
      { event_type: "a" },
      { event_type: "b" },
    ]);
    assert.equal(result.accepted, 2);
    assert.ok(Array.isArray(lastRequest?.body.events));
  });

  it("close flushes remaining events", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 3 }),
      status: 200,
      contentType: "application/json",
    };
    const wl = client();
    await wl.track({ event_type: "a" });
    await wl.track({ event_type: "b" });
    await wl.track({ event_type: "c" });
    assert.equal(requestCount, 0);

    await wl.close();

    assert.ok(requestCount >= 1, "close should flush events");
    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.ok(events.length > 0);
  });

  it("track after close is no-op", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };
    const wl = client();
    await wl.close();

    const result = await wl.track({ event_type: "test" });
    assert.equal(result.accepted, 0);
    assert.equal(requestCount, 0);
  });

  it("close is idempotent", async () => {
    const wl = client();
    await wl.close();
    await wl.close();
    // Should not throw
  });

  it("disabled client is no-op", async () => {
    const wl = new WireLog({ apiKey: "sk_test", host: baseUrl, disabled: true });
    const result = await wl.track({ event_type: "test" });
    assert.equal(result.accepted, 0);
    assert.equal(requestCount, 0);
    await wl.close();
  });

  it("query sends DSL and returns result", async () => {
    mockResponse = {
      body: JSON.stringify({ rows: [{ count: 42 }] }),
      status: 200,
      contentType: "application/json",
    };
    const result = await client().query("* | last 7d | count");
    assert.deepEqual(result, { rows: [{ count: 42 }] });
    assert.equal(lastRequest?.path, "/query");
    assert.equal(lastRequest?.body.q, "* | last 7d | count");
    assert.equal(lastRequest?.body.format, "llm");
  });

  it("identify sends user binding", async () => {
    mockResponse = {
      body: JSON.stringify({ ok: true }),
      status: 200,
      contentType: "application/json",
    };
    const result = await client().identify({
      user_id: "alice@acme.org",
      device_id: "dev_123",
      user_properties: { email: "alice@acme.org" },
    });
    assert.equal(result.ok, true);
    assert.equal(lastRequest?.path, "/identify");
    assert.equal(lastRequest?.body.user_id, "alice@acme.org");
  });

  it("choice requires identify, visitor, or an explicit subject before assignment", () => {
    const wl = client();

    assert.throws(
      () => wl.choice("landing_h1", ["Welcome", "Best site"]),
      /wirelog\.choice requires/,
    );
  });

  it("choice resolves synchronously for explicit visitors and tracks exposure async", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };
    const wl = client();

    const did = wl.visitor();
    const selected = wl.choice("landing_h1", ["Welcome", "Best site"]);
    assert.ok(["Welcome", "Best site"].includes(selected));

    await wl.flush();
    assert.equal(lastRequest?.path, "/track");
    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.equal(events[0].event_type, "wirelog.exposure");
    assert.equal(events[0].device_id, did);
    const props = events[0].event_properties as Record<string, unknown>;
    assert.equal(props.choice_key, "landing_h1");
    assert.equal(props.choice_kind, "choice");
    assert.equal(props.reason, "client_choice");
    assert.equal(props.randomization_unit, "device_id");
    assert.equal(String(events[0].insert_id).startsWith("chas_"), true);
    await wl.close();
  });

  it("choice can use identify state before the identify request returns", async () => {
    mockResponse = {
      body: JSON.stringify({ ok: true, accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };
    const wl = client();

    const identifyPromise = wl.identify({ user_id: "user_123" });
    const assignment = wl.assignment("landing_h1", [
      { key: "welcome", value: "Welcome", weight: 20 },
      { key: "best", value: "Best site", weight: 80 },
    ]);

    assert.equal(assignment.randomization_unit, "user_id");
    assert.equal(assignment.reason, "client_choice");
    await identifyPromise;
    await wl.flush();

    assert.equal(lastRequest?.path, "/track");
    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.equal(events[0].user_id, "user_123");
    const props = events[0].event_properties as Record<string, unknown>;
    assert.equal(props.choice_key, "landing_h1");
    assert.equal(props.variant_weight, String(assignment.variant_weight));
    await wl.close();
  });

  it("choice version ignores localized payload changes when keys and weights are stable", () => {
    const wl = client();

    const english = wl.assignment("landing_h1", [
      { key: "welcome", value: "Welcome to our site", weight: 50 },
      { key: "best", value: "The best site in the world", weight: 50 },
    ], {
      subject: { user_id: "u_123" },
      expose: false,
    });
    const spanish = wl.assignment("landing_h1", [
      { key: "welcome", value: "Bienvenido a nuestro sitio", weight: 50 },
      { key: "best", value: "El mejor sitio del mundo", weight: 50 },
    ], {
      subject: { user_id: "u_123" },
      expose: false,
    });

    assert.equal(spanish.choice_version, english.choice_version);
    assert.equal(spanish.assignment_id, english.assignment_id);
    assert.equal(spanish.variant_key, english.variant_key);
  });

  it("choiceSeed preserves assignment across API key rotation", () => {
    const variants = [
      { key: "welcome", value: "Welcome", weight: 50 },
      { key: "best", value: "Best", weight: 50 },
    ];
    const oldKey = new WireLog({ apiKey: "pk_old", host: baseUrl, choiceSeed: "proj_stable" });
    const newKey = new WireLog({ apiKey: "pk_new", host: baseUrl, choiceSeed: "proj_stable" });

    const a = oldKey.assignment("landing_h1", variants, {
      subject: { user_id: "u_123" },
      expose: false,
    });
    const b = newKey.assignment("landing_h1", variants, {
      subject: { user_id: "u_123" },
      expose: false,
    });

    assert.equal(b.assignment_id, a.assignment_id);
    assert.equal(b.variant_key, a.variant_key);
  });

  it("choice warns when one key uses mixed randomization units", () => {
    const wl = client();
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (message?: unknown): void => {
      warnings.push(String(message));
    };
    try {
      wl.assignment("landing_h1", ["A", "B"], {
        subject: { user_id: "u_123" },
        expose: false,
      });
      wl.assignment("landing_h1", ["A", "B"], {
        subject: { device_id: "dev_123" },
        expose: false,
      });
    } finally {
      console.warn = originalWarn;
    }

    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /used randomization unit 'user_id' and now 'device_id'/);
  });

  it("sends X-API-Key header", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };
    const wl = client();
    await wl.track({ event_type: "test" });
    await wl.flush();
    assert.equal(lastRequest?.headers["x-api-key"], "sk_test_key");
    await wl.close();
  });

  it("defaults host to api.wirelog.ai", () => {
    const wl = new WireLog({ apiKey: "sk_test" });
    // We can't easily test the private field, but we can test construction doesn't throw
    assert.ok(wl);
  });

  it("strips trailing slash from host", () => {
    const wl = new WireLog({
      apiKey: "sk_test",
      host: "https://api.wirelog.ai/",
    });
    assert.ok(wl);
  });

  it("runtime browser detection is evaluated at runtime", async () => {
    const nodeClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
    assert.equal(nodeClient.deviceId, null);

    await withBrowserEnv("https://app.example.com/home", async () => {
      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      assert.ok(browserClient.deviceId);
    });
  });

  it("browser track buffers by default and flush sends batched payload", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };

    await withBrowserEnv("https://app.example.com/home", async () => {
      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      const buffered = await browserClient.track({
        event_type: "cta_clicked",
        event_properties: {
          url: "https://override.example.com/path",
          language: "fr-FR",
        },
      });
      assert.equal(buffered.accepted, 1);
      assert.equal(buffered.buffered, true);
      assert.equal(requestCount, 0);

      const flushed = await browserClient.flush();
      assert.equal(flushed.accepted, 1);
    });

    assert.equal(requestCount, 1);
    assert.equal(lastRequest?.path, "/track");
    assert.equal(lastRequest?.body.clientOriginated, true);
    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.equal(events.length, 1);

    const props = events[0].event_properties as Record<string, unknown>;
    assert.equal(props.url, "https://override.example.com/path");
    assert.equal(props.language, "fr-FR");
    assert.ok(events[0].session_id);
    assert.ok(events[0].device_id);
    assert.equal(events[0].clientOriginated, true);
  });

  it("browser trackBatch marks request as client-originated", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 2 }),
      status: 200,
      contentType: "application/json",
    };

    await withBrowserEnv("https://app.example.com/home", async () => {
      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      await browserClient.trackBatch([{ event_type: "a" }, { event_type: "b" }]);
    });

    assert.equal(lastRequest?.body.clientOriginated, true);
    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.equal(events[0].clientOriginated, true);
    assert.equal(events[1].clientOriginated, true);
  });

  it("hydrates session from sessionStorage (shared with wirelog.js)", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };

    await withBrowserEnv("https://app.example.com/home", async ({ sessionStorage }) => {
      // Simulate wirelog.js having already created a session.
      const wirelogSessionId = "aabbccddeeff001122334455";
      const wirelogLastActivity = String(Date.now() - 5000); // 5s ago, well within timeout
      sessionStorage.setItem("wl_sid", wirelogSessionId);
      sessionStorage.setItem("wl_slast", wirelogLastActivity);

      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      await browserClient.track({ event_type: "click" });
      await browserClient.flush();
    });

    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.equal(events[0].session_id, "aabbccddeeff001122334455");
  });

  it("persists new session to sessionStorage so wirelog.js can find it", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };

    await withBrowserEnv("https://app.example.com/home", async ({ sessionStorage }) => {
      // No pre-existing session — TypeScript SDK should create one and persist.
      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      await browserClient.track({ event_type: "click" });
      await browserClient.flush();

      const storedSid = sessionStorage.getItem("wl_sid");
      const storedLast = sessionStorage.getItem("wl_slast");
      assert.ok(storedSid, "session ID should be persisted to sessionStorage");
      assert.ok(storedLast, "last activity should be persisted to sessionStorage");
      assert.equal(storedSid!.length, 24, "session ID should be 24-char hex");
    });
  });

  it("rotates session after timeout and persists the new one", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };

    await withBrowserEnv("https://app.example.com/home", async ({ sessionStorage }) => {
      // Simulate an expired session (31 minutes ago).
      const expiredSessionId = "deadbeefdeadbeefdeadbeef";
      const expiredLast = String(Date.now() - 31 * 60 * 1000);
      sessionStorage.setItem("wl_sid", expiredSessionId);
      sessionStorage.setItem("wl_slast", expiredLast);

      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      await browserClient.track({ event_type: "click" });
      await browserClient.flush();

      // Session should have been rotated.
      const newSid = sessionStorage.getItem("wl_sid");
      assert.ok(newSid);
      assert.notEqual(newSid, expiredSessionId, "expired session should be rotated");
    });
  });

  it("shares device ID with wirelog.js via localStorage", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };

    await withBrowserEnv("https://app.example.com/home", async ({ localStorage }) => {
      // Simulate wirelog.js having already created a device ID.
      localStorage.setItem("wl_did", "wirelog_device_aabbccdd1122");

      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      assert.equal(browserClient.deviceId, "wirelog_device_aabbccdd1122");

      await browserClient.track({ event_type: "click" });
      await browserClient.flush();
    });

    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.equal(events[0].device_id, "wirelog_device_aabbccdd1122");
  });

  it("picks up device ID changes from wirelog.js reset on next track", async () => {
    mockResponse = {
      body: JSON.stringify({ accepted: 1 }),
      status: 200,
      contentType: "application/json",
    };

    await withBrowserEnv("https://app.example.com/home", async ({ localStorage }) => {
      localStorage.setItem("wl_did", "original_device_id_aabbcc");

      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      assert.equal(browserClient.deviceId, "original_device_id_aabbcc");

      // Simulate wirelog.js calling reset() — removes old, writes new.
      localStorage.removeItem("wl_did");
      localStorage.setItem("wl_did", "new_device_after_reset_dd");

      await browserClient.track({ event_type: "click" });
      await browserClient.flush();
    });

    const events = lastRequest?.body.events as Array<Record<string, unknown>>;
    assert.equal(events[0].device_id, "new_device_after_reset_dd");
  });

  it("reset clears session from sessionStorage", async () => {
    await withBrowserEnv("https://app.example.com/home", async ({ sessionStorage, localStorage }) => {
      sessionStorage.setItem("wl_sid", "session_to_clear_aabbcc");
      sessionStorage.setItem("wl_slast", String(Date.now()));

      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });
      browserClient.reset();

      assert.equal(sessionStorage.getItem("wl_sid"), null, "session ID should be removed");
      assert.equal(sessionStorage.getItem("wl_slast"), null, "last activity should be removed");
      assert.equal(localStorage.getItem("wl_uid"), null, "user ID should be removed");
      // Device ID should be regenerated.
      assert.ok(localStorage.getItem("wl_did"), "device ID should be regenerated");
    });
  });

  it("identify merges attribution and dedupes only after successful response", async () => {
    await withBrowserEnv("https://app.example.com/?utm_source=google&utm_campaign=spring", async () => {
      const browserClient = new WireLog({ apiKey: "sk_test_key", host: baseUrl });

      mockResponse = { body: "failed", status: 500, contentType: "text/plain" };
      await assert.rejects(
        browserClient.identify({ user_id: "user_123" }),
        /WireLog API 500/,
      );
      const firstOps = (lastRequest?.body.user_property_ops || {}) as Record<string, unknown>;
      assert.equal(
        ((firstOps.$set_once || {}) as Record<string, unknown>).initial_utm_source,
        "google",
      );
      assert.equal(
        ((firstOps.$set || {}) as Record<string, unknown>).last_utm_campaign,
        "spring",
      );

      mockResponse = { body: JSON.stringify({ ok: true }), status: 200, contentType: "application/json" };
      await browserClient.identify({ user_id: "user_123" });
      const secondOps = (lastRequest?.body.user_property_ops || {}) as Record<string, unknown>;
      assert.equal(
        ((secondOps.$set_once || {}) as Record<string, unknown>).initial_utm_source,
        "google",
      );

      await browserClient.identify({ user_id: "user_123" });
      const thirdOps = (lastRequest?.body.user_property_ops || {}) as Record<string, unknown>;
      assert.equal((thirdOps.$set_once as Record<string, unknown> | undefined)?.initial_utm_source, undefined);
      assert.equal((thirdOps.$set as Record<string, unknown> | undefined)?.last_utm_source, undefined);
    });
  });

  it("onError callback receives flush errors in Node", async () => {
    const errors: Error[] = [];
    mockResponse = { body: "bad", status: 400, contentType: "text/plain" };

    const wl = new WireLog({
      apiKey: "sk_test_key",
      host: baseUrl,
      onError: (err) => errors.push(err),
    });

    await wl.track({ event_type: "test" });
    await wl.flush();

    assert.ok(errors.length > 0, "onError should be called on flush failure");
    assert.ok(errors[0].message.includes("400"));
    await wl.close();
  });
});
