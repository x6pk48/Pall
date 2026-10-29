'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('node:net');
const { createGatewayServer } = require('../gateway');

async function startGateway(options) {
  const server = createGatewayServer(options);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { server, url: `http://127.0.0.1:${port}` };
}

async function closeGateway(server) {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test('requires both Nebius and local gateway credentials', () => {
  assert.throws(() => createGatewayServer({ apiKey: '', gatewayToken: 'local-token' }), /NEBIUS_API_KEY/);
  assert.throws(() => createGatewayServer({ apiKey: 'nebius-key', gatewayToken: '' }), /PALL_GATEWAY_TOKEN/);
});

test('forwards authorized redacted completions using the server-side Nebius key', async (t) => {
  let upstreamRequest;
  const payload = { model: 'nvidia/nemotron-3-super-120b-a12b', messages: [{ role: 'user', content: 'Summarize [PERSON_1] account [SECRET_api_key_123abc].' }] };
  const { server, url } = await startGateway({
    apiKey: 'server-only-key',
    gatewayToken: 'extension-token',
    baseUrl: 'https://nebius.example/v1',
    fetchImpl: async (target, options) => {
      upstreamRequest = { target, options };
      return new Response(JSON.stringify({ choices: [{ message: { content: 'Done' } }] }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  t.after(() => closeGateway(server));

  const response = await fetch(`${url}/v1/chat/completions`, {
    method: 'POST',
    headers: { Authorization: 'Bearer extension-token', 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { choices: [{ message: { content: 'Done' } }] });
  assert.equal(upstreamRequest.target, 'https://nebius.example/v1/chat/completions');
  assert.equal(upstreamRequest.options.headers.Authorization, 'Bearer server-only-key');
  assert.deepEqual(JSON.parse(upstreamRequest.options.body), payload);
});

test('rejects invalid local tokens before contacting Nebius', async (t) => {
  let calledUpstream = false;
  const { server, url } = await startGateway({ apiKey: 'server-only-key', gatewayToken: 'expected-token', fetchImpl: async () => { calledUpstream = true; } });
  t.after(() => closeGateway(server));

  const response = await fetch(`${url}/v1/chat/completions`, {
    method: 'POST',
    headers: { Authorization: 'Bearer wrong-token', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'nvidia/nemotron-3-nano-30b-a3b', messages: [] })
  });

  assert.equal(response.status, 401);
  assert.equal(calledUpstream, false);
});

test('blocks unredacted secrets and PII before contacting Nebius', async (t) => {
  let calledUpstream = false;
  const { server, url } = await startGateway({ apiKey: 'server-only-key', gatewayToken: 'extension-token', fetchImpl: async () => { calledUpstream = true; } });
  t.after(() => closeGateway(server));

  const response = await fetch(`${url}/v1/chat/completions`, {
    method: 'POST',
    headers: { Authorization: 'Bearer extension-token', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'nvidia/nemotron-3-nano-30b-a3b', messages: [{ role: 'user', content: 'Email me at alice@example.com' }] })
  });

  assert.equal(response.status, 422);
  assert.match((await response.json()).error.message, /Egress blocked/);
  assert.equal(calledUpstream, false);
});

test('rejects browser requests from unknown origins', async (t) => {
  let calledUpstream = false;
  const { server, url } = await startGateway({ apiKey: 'server-only-key', gatewayToken: 'extension-token', fetchImpl: async () => { calledUpstream = true; } });
  t.after(() => closeGateway(server));

  const response = await fetch(`${url}/v1/chat/completions`, {
    method: 'POST',
    headers: { Origin: 'https://attacker.example', Authorization: 'Bearer extension-token', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'nvidia/nemotron-3-nano-30b-a3b', messages: [] })
  });

  assert.equal(response.status, 403);
  assert.equal(calledUpstream, false);
});

test('serves a local health check without contacting Nebius', async (t) => {
  const { server, url } = await startGateway({ apiKey: 'server-only-key', gatewayToken: 'extension-token', fetchImpl: async () => { throw new Error('unexpected upstream call'); } });
  t.after(() => closeGateway(server));

  const response = await fetch(`${url}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true, provider: 'Nebius Token Factory' });
});

test('reports sanitized upstream connection codes without leaking exception messages', async (t) => {
  const messages = [];
  const originalError = console.error;
  console.error = (message) => messages.push(message);
  t.after(() => { console.error = originalError; });
  const { server, url } = await startGateway({
    apiKey: 'server-only-key',
    gatewayToken: 'extension-token',
    fetchImpl: async () => { const error = new Error('private request details'); error.cause = { code: 'ECONNRESET' }; throw error; }
  });
  t.after(() => closeGateway(server));

  const response = await fetch(`${url}/v1/chat/completions`, {
    method: 'POST',
    headers: { Authorization: 'Bearer extension-token', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'nvidia/nemotron-3-nano-30b-a3b', messages: [{ role: 'user', content: 'hello' }] })
  });
  const body = await response.json();

  assert.equal(response.status, 502);
  assert.match(body.error.message, /ECONNRESET/);
  assert.doesNotMatch(body.error.message, /private request details|server-only-key/);
  assert.match(messages[0], /ECONNRESET/);
  assert.doesNotMatch(messages[0], /private request details|server-only-key/);
});
