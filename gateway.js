#!/usr/bin/env node
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const HOST = '127.0.0.1';
const PORT = Number(process.env.PALL_GATEWAY_PORT || 8787);
const NEBIUS_BASE_URL = (process.env.NEBIUS_BASE_URL || 'https://api.tokenfactory.nebius.com/v1').replace(/\/$/, '');
const MAX_BODY_BYTES = 1024 * 1024;

const sensitivePatterns = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b(?:sk|nvapi|rk|pk)-[A-Za-z0-9_-]{16,}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  /\b\d{3}-\d{2}-\d{4}\b/
];

function findSensitiveText(value, path = 'request') {
  if (typeof value === 'string') {
    return sensitivePatterns.some((pattern) => pattern.test(value)) ? path : null;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      const found = findSensitiveText(value[index], `${path}[${index}]`);
      if (found) return found;
    }
  } else if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const found = findSensitiveText(child, `${path}.${key}`);
      if (found) return found;
    }
  }
  return null;
}

function allowedOrigin(origin) {
  return !origin || /^chrome-extension:\/\/[a-p]{32}$/.test(origin) || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

function sendJson(response, status, value, origin) {
  if (origin && allowedOrigin(origin)) response.setHeader('Access-Control-Allow-Origin', origin);
  response.setHeader('Vary', 'Origin');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.statusCode = status;
  response.end(JSON.stringify(value), 'utf8');
}

function createGatewayServer({ apiKey, gatewayToken, baseUrl = NEBIUS_BASE_URL, fetchImpl = fetch }) {
  if (!apiKey) throw new Error('NEBIUS_API_KEY is required.');
  if (!gatewayToken) throw new Error('PALL_GATEWAY_TOKEN is required.');

  return http.createServer(async (request, response) => {
    const origin = request.headers.origin;
    if (!allowedOrigin(origin)) return sendJson(response, 403, { error: { message: 'Origin not allowed.' } });
    if (origin) {
      response.setHeader('Access-Control-Allow-Origin', origin);
      response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
      response.setHeader('Vary', 'Origin');
    }
    if (request.method === 'OPTIONS') {
      response.statusCode = 204;
      return response.end();
    }
    if (request.method === 'GET' && request.url === '/health') {
      response.statusCode = 200;
      response.setHeader('Content-Type', 'application/json; charset=utf-8');
      return response.end(JSON.stringify({ ok: true, provider: 'Nebius Token Factory' }));
    }
    if (request.method !== 'POST' || request.url !== '/v1/chat/completions') {
      return sendJson(response, 404, { error: { message: 'Not found.' } });
    }

    const authorization = request.headers.authorization || '';
    const suppliedToken = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    const expected = Buffer.from(gatewayToken);
    const supplied = Buffer.from(suppliedToken);
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) {
      return sendJson(response, 401, { error: { message: 'Invalid gateway token.' } }, origin);
    }

    let raw = '';
    try {
      for await (const chunk of request) {
        raw += chunk;
        if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) {
          return sendJson(response, 413, { error: { message: 'Request body is too large.' } }, origin);
        }
      }
      const payload = JSON.parse(raw);
      if (!payload || !Array.isArray(payload.messages) || typeof payload.model !== 'string') {
        return sendJson(response, 400, { error: { message: 'Expected a model and messages array.' } }, origin);
      }
      const sensitivePath = findSensitiveText(payload.messages, 'messages');
      if (sensitivePath) {
        return sendJson(response, 422, { error: { message: `Egress blocked: unredacted sensitive text at ${sensitivePath}.` } }, origin);
      }

      const upstream = await fetchImpl(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const body = await upstream.text();
      response.statusCode = upstream.status;
      response.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/json; charset=utf-8');
      response.end(body);
    } catch (error) {
      if (response.headersSent) return response.destroy();
      const code = error && error.cause && error.cause.code;
      const name = error && error.name;
      const detail = code || (name && name !== 'Error' ? name : 'upstream connection error');
      console.error(`Nebius upstream request failed (${detail}).`);
      sendJson(response, 502, { error: { message: `Nebius Token Factory request failed (${detail}).` } }, origin);
    }
  });
}

if (require.main === module) {
  const apiKey = process.env.NEBIUS_API_KEY;
  let gatewayToken = process.env.PALL_GATEWAY_TOKEN;
  if (!gatewayToken) {
    gatewayToken = crypto.randomBytes(24).toString('base64url');
    process.env.PALL_GATEWAY_TOKEN = gatewayToken;
    console.log(`Generated Pall gateway token: ${gatewayToken}`);
  }
  try {
    const server = createGatewayServer({ apiKey, gatewayToken });
    server.listen(PORT, HOST, () => {
      console.log(`Pall gateway listening at http://${HOST}:${PORT}`);
      console.log('Set the extension Gateway URL to http://127.0.0.1:8787/v1 and paste the token in Settings.');
    });
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { createGatewayServer, findSensitiveText };