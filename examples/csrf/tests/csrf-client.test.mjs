import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../static/csrf-client.js", import.meta.url), "utf8");
const { attachCsrfClient, createCsrfClient } = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
);

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function csrfRejection() {
  return new Response("rejected", {
    status: 403,
    headers: { "X-Rocket-CSRF": "csrf-failure" },
  });
}

test("concurrent initial bootstrap calls share one request", async () => {
  const calls = [];
  let resolveBootstrap;
  const client = createCsrfClient((url, init) => {
    calls.push({ url, init });
    if (url === "/api/bootstrap") {
      return new Promise(resolve => { resolveBootstrap = resolve; });
    }

    return Promise.resolve(new Response("ok", { status: 200 }));
  });

  const first = client.sendMessage("first");
  const second = client.sendMessage("second");
  assert.equal(calls.filter(call => call.url === "/api/bootstrap").length, 1);
  resolveBootstrap(jsonResponse("shared-token"));
  await Promise.all([first, second]);
  await client.sendMessage("third");

  const posts = calls.filter(call => call.url === "/api/message");
  assert.equal(posts.length, 3);
  assert.equal(calls.filter(call => call.url === "/api/bootstrap").length, 1);
  assert.deepEqual(posts.map(call => call.init.headers["X-XSRF-TOKEN"]), [
    "shared-token",
    "shared-token",
    "shared-token",
  ]);
});

test("explicit 403 marker refreshes once and reuses the identical mutation body", async () => {
  const calls = [];
  let tokenNumber = 0;
  let postNumber = 0;
  const client = createCsrfClient((url, init) => {
    calls.push({ url, init });
    if (url === "/api/bootstrap") {
      tokenNumber += 1;
      return Promise.resolve(jsonResponse(`token-${tokenNumber}`));
    }

    postNumber += 1;
    return Promise.resolve(postNumber === 1
      ? csrfRejection()
      : new Response("accepted", { status: 200 }));
  });

  const response = await client.sendMessage("preserve this payload");
  assert.equal(response.status, 200);
  assert.equal(calls.filter(call => call.url === "/api/bootstrap").length, 2);
  const posts = calls.filter(call => call.url === "/api/message");
  assert.equal(posts.length, 2);
  assert.equal(posts[0].init.body, posts[1].init.body);
  assert.deepEqual(posts.map(call => call.init.headers["X-XSRF-TOKEN"]), [
    "token-1",
    "token-2",
  ]);
});

test("authorization and swallowed-guard 403 responses are never retried", async t => {
  for (const scenario of [
    { name: "application authorization", response: new Response("forbidden", { status: 403 }) },
    { name: "swallowed guard failure", response: new Response("mutated", { status: 403 }) },
    {
      name: "marker without a 403 status",
      response: new Response("not forbidden", {
        status: 500,
        headers: { "X-Rocket-CSRF": "csrf-failure" },
      }),
    },
  ]) {
    await t.test(scenario.name, async () => {
      const calls = [];
      const client = createCsrfClient((url, init) => {
        calls.push({ url, init });
        return Promise.resolve(url === "/api/bootstrap"
          ? jsonResponse("token")
          : scenario.response);
      });

      const response = await client.sendMessage("mutation");
      assert.equal(response.status, scenario.response.status);
      assert.equal(calls.filter(call => call.url === "/api/bootstrap").length, 1);
      assert.equal(calls.filter(call => call.url === "/api/message").length, 1);
    });
  }
});

test("a second marked rejection is returned without a second retry", async () => {
  let bootstrapCount = 0;
  let postCount = 0;
  const client = createCsrfClient(url => {
    if (url === "/api/bootstrap") {
      bootstrapCount += 1;
      return Promise.resolve(jsonResponse(`token-${bootstrapCount}`));
    }

    postCount += 1;
    return Promise.resolve(csrfRejection());
  });

  const response = await client.sendMessage("once only");
  assert.equal(response.status, 403);
  assert.equal(bootstrapCount, 2);
  assert.equal(postCount, 2);
});

test("bootstrap errors and network failures reach the UI", async t => {
  await t.test("non-success bootstrap response", async () => {
    let posts = 0;
    const client = createCsrfClient(url => Promise.resolve(url === "/api/bootstrap"
      ? jsonResponse({}, 503)
      : (posts += 1, new Response("unexpected"))));
    const output = { textContent: "" };
    let click;
    attachCsrfClient(client, { addEventListener: (_, handler) => { click = handler; } }, output);

    await click();
    assert.match(output.textContent, /CSRF bootstrap failed \(503\)/);
    assert.equal(posts, 0);
  });

  await t.test("network failure", async () => {
    const client = createCsrfClient(() => Promise.reject(new Error("offline")));
    const output = { textContent: "" };
    let click;
    attachCsrfClient(client, { addEventListener: (_, handler) => { click = handler; } }, output);

    await click();
    assert.match(output.textContent, /CSRF\/network error: offline/);
  });
});
