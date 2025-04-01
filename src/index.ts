#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import crypto from 'crypto'
import { Redis } from '@upstash/redis'

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio';
  // Storage modes: "memory-single", "memory", or "upstash-redis-rest"
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  xClientId: string;
  xClientSecret: string;
  xRedirectUri: string;
  // For storage "memory" and "upstash-redis-rest": the header name (or key prefix) to use.
  storageHeaderKey?: string;
  // Upstash-specific options (if storage is "upstash-redis-rest")
  upstashRedisRestUrl?: string;
  upstashRedisRestToken?: string;
}

interface Storage {
  get(memoryKey: string): Promise<{ accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string } | undefined>;
  set(memoryKey: string, data: { accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string }): Promise<void>;
}

// --------------------------------------------------------------------
// In-Memory Storage Implementation
// --------------------------------------------------------------------
class MemoryStorage implements Storage {
  private storage: Record<string, { accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string }> = {};

  async get(memoryKey: string) {
    return this.storage[memoryKey];
  }

  async set(memoryKey: string, data: { accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string }) {
    // Merge with existing data if any.
    this.storage[memoryKey] = { ...this.storage[memoryKey], ...data };
  }
}

// --------------------------------------------------------------------
// Upstash Redis Storage Implementation
// --------------------------------------------------------------------
class RedisStorage implements Storage {
  private redis: Redis;
  private keyPrefix: string;

  constructor(redisUrl: string, redisToken: string, keyPrefix: string) {
    this.redis = new Redis({ url: redisUrl, token: redisToken });
    this.keyPrefix = keyPrefix;
  }

  async get(memoryKey: string): Promise<{ accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string } | undefined> {
    const data = await this.redis.get<string>(`${this.keyPrefix}:${memoryKey}`);
    if (!data) return undefined;
    try {
      return JSON.parse(data);
    } catch (err) {
      return undefined;
    }
  }

  async set(memoryKey: string, data: { accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string }) {
    const existing = (await this.get(memoryKey)) || {};
    const newData = { ...existing, ...data };
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(newData));
  }
}

// --------------------------------------------------------------------
// PKCE Code Generation for OAuth
// --------------------------------------------------------------------
function generatePKCECodes(): { codeVerifier: string; codeChallenge: string } {
  const randomBytes = crypto.randomBytes(32);
  const codeVerifier = randomBytes.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  const codeChallenge = hash.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  return { codeVerifier, codeChallenge };
}

// --------------------------------------------------------------------
// OAuth Helper Functions (using config)
// --------------------------------------------------------------------
function generateAuthUrl(config: Config, storage: Storage, memoryKey: string): string {
  const pkce = generatePKCECodes();
  // Save the code verifier for later use.
  storage.set(memoryKey, { codeVerifier: pkce.codeVerifier });
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.xClientId,
    redirect_uri: config.xRedirectUri,
    // Request tweet.read, users.read, tweet.write and offline.access scopes.
    scope: 'tweet.read users.read tweet.write offline.access',
    state: 'state', // In production, use a random value to mitigate CSRF.
    code_challenge: pkce.codeChallenge,
    code_challenge_method: 'S256'
  });
  return `https://x.com/i/oauth2/authorize?${params.toString()}`;
}

async function exchangeAuthCode(code: string, config: Config, storage: Storage, memoryKey: string): Promise<string> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.codeVerifier) {
    throw new Error('No PKCE code verifier found. Generate auth URL first.');
  }
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code.trim(),
    redirect_uri: config.xRedirectUri,
    code_verifier: stored.codeVerifier,
  });
  params.append('client_id', config.xClientId);
  const basicAuth = Buffer.from(`${config.xClientId}:${config.xClientSecret}`).toString('base64');
  const response = await fetch('https://api.x.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`
    },
    body: params.toString()
  });
  const data = await response.json();
  if (!data.access_token) {
    throw new Error('Failed to obtain X access token.');
  }
  await storage.set(memoryKey, { accessToken: data.access_token, refreshToken: data.refresh_token });
  return data.access_token;
}

async function autorefreshFetch(url: string, options: RequestInit, config: Config, storage: Storage, memoryKey: string): Promise<globalThis.Response> {
  let stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken) throw new Error('No X access token available.');
  if (!options.headers || typeof options.headers !== 'object') {
    options.headers = {};
  }
  (options.headers as Record<string, string>)['Authorization'] = `Bearer ${stored.accessToken}`;
  let response = await fetch(url, options) as globalThis.Response;
  if (response.status === 401) {
    try {
      await refreshAccessToken(config, storage, memoryKey);
      stored = await storage.get(memoryKey);
      (options.headers as Record<string, string>)['Authorization'] = `Bearer ${stored?.accessToken}`;
      response = await fetch(url, options) as globalThis.Response;
    } catch (err: any) {
      throw new Error("Token refresh failed: " + err.message);
    }
  }
  return response;
}

async function refreshAccessToken(config: Config, storage: Storage, memoryKey: string): Promise<string> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.refreshToken) throw new Error("No refresh token available.");
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: stored.refreshToken,
    client_id: config.xClientId
  });
  const basicAuth = Buffer.from(`${config.xClientId}:${config.xClientSecret}`).toString('base64');
  const response = await fetch('https://api.x.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`
    },
    body: params.toString()
  });
  const data = await response.json();
  if (!data.access_token) {
    throw new Error('Failed to refresh X access token.');
  }
  await storage.set(memoryKey, { accessToken: data.access_token, refreshToken: data.refresh_token });
  return data.access_token;
}

async function fetchUser(config: Config, storage: Storage, memoryKey: string): Promise<any> {
  const response = await autorefreshFetch('https://api.x.com/2/users/me', {}, config, storage, memoryKey);
  const data = await response.json() as { data: { id: string } };
  if (!data.data || !data.data.id) {
    throw new Error('Failed to fetch X user id.');
  }
  await storage.set(memoryKey, { userId: data.data.id });
  return data.data;
}

async function auth(args: { code: string; memoryKey: string; config: Config; storage: Storage }): Promise<any> {
  const { code, memoryKey, config, storage } = args;
  await exchangeAuthCode(code, config, storage, memoryKey);
  const user = await fetchUser(config, storage, memoryKey);
  return { success: true, provider: "x", user };
}

async function createTweetTool(args: { tweetContent: string; memoryKey: string; config: Config; storage: Storage }): Promise<any> {
  const { tweetContent, memoryKey, config, storage } = args;
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken || !stored.userId) {
    throw new Error(`No X authentication configured for key "${memoryKey}". Run x_exchange_auth_code first.`);
  }
  const postData = { text: tweetContent };
  const response = await autorefreshFetch('https://api.x.com/2/tweets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(postData)
  }, config, storage, memoryKey);
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`X tweet creation failed: ${errorText}`);
  }
  return { success: true, message: 'Tweet created successfully.' };
}

async function getTweetsTool(args: { query: string; memoryKey: string; config: Config; storage: Storage }): Promise<any> {
  const { query, memoryKey, config, storage } = args;
  const url = `https://api.x.com/2/tweets/search/recent?query=${encodeURIComponent(query)}`;
  const response = await autorefreshFetch(url, {}, config, storage, memoryKey);
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`X get tweets failed: ${errorText}`);
  }
  const data = await response.json();
  return data;
}

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

// --------------------------------------------------------------------
// Create an X MCP server
// This function creates the storage instance based on the config and returns
// an MCP server using the provided memoryKey.
// --------------------------------------------------------------------
function createXServer(memoryKey: string, config: Config): McpServer {
  let storage: Storage;
  if (config.storage === 'upstash-redis-rest') {
    storage = new RedisStorage(
      config.upstashRedisRestUrl!,
      config.upstashRedisRestToken!,
      config.storageHeaderKey!
    );
  } else {
    storage = new MemoryStorage();
  }
  const server = new McpServer({
    name: `X MCP Server (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  });

  server.tool(
    'x_auth_url',
    'Return an OAuth URL for X (visit this URL to grant access with tweet.read, users.read, tweet.write, and offline.access scopes).',
    {},
    async () => {
      try {
        const authUrl = generateAuthUrl(config, storage, memoryKey);
        return toTextJson({ authUrl });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'x_exchange_auth_code',
    'Set up X authentication by exchanging an auth code.',
    { code: z.string() },
    async (args) => {
      try {
        const result = await auth({ code: args.code, memoryKey, config, storage });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'x_create_tweet',
    'Create a new tweet on X on behalf of the authenticated user. Provide tweetContent as text.',
    { tweetContent: z.string() },
    async (args) => {
      try {
        const result = await createTweetTool({ tweetContent: args.tweetContent, memoryKey, config, storage });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'x_get_tweets',
    'Search for recent tweets on X. Provide a query string to search for tweets.',
    { query: z.string() },
    async (args) => {
      try {
        const result = await getTweetsTool({ query: args.query, memoryKey, config, storage });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  return server;
}

// --------------------------------------------------------------------
// Logging Helpers
// --------------------------------------------------------------------
function log(...args: any[]) {
  console.log('[x-mcp]', ...args);
}

function logErr(...args: any[]) {
  console.error('[x-mcp]', ...args);
}

// --------------------------------------------------------------------
// Main: Start the server
// --------------------------------------------------------------------
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
    .option('storage', {
      type: 'string',
      choices: ['memory-single', 'memory', 'upstash-redis-rest'],
      default: 'memory-single',
      describe:
        'Choose storage backend: "memory-single" uses fixed single-user storage; "memory" uses multi-user in-memory storage (requires --storageHeaderKey); "upstash-redis-rest" uses Upstash Redis (requires --storageHeaderKey, --upstashRedisRestUrl, and --upstashRedisRestToken).'
    })
    .option('xClientId', { type: 'string', demandOption: true, describe: "X Client ID" })
    .option('xClientSecret', { type: 'string', demandOption: true, describe: "X Client Secret" })
    .option('xRedirectUri', { type: 'string', demandOption: true, describe: "X Redirect URI" })
    .option('storageHeaderKey', { type: 'string', describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.' })
    .option('upstashRedisRestUrl', { type: 'string', describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)' })
    .option('upstashRedisRestToken', { type: 'string', describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)' })
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio',
    storage: argv.storage as 'memory-single' | 'memory' | 'upstash-redis-rest',
    xClientId: argv.xClientId,
    xClientSecret: argv.xClientSecret,
    xRedirectUri: argv.xRedirectUri,
    storageHeaderKey:
      (argv.storage === 'memory-single')
        ? undefined
        : (argv.storageHeaderKey && argv.storageHeaderKey.trim()
          ? argv.storageHeaderKey.trim()
          : (() => { logErr('Error: --storageHeaderKey is required for storage modes "memory" or "upstash-redis-rest".'); process.exit(1); return ''; })()),
    upstashRedisRestUrl: argv.upstashRedisRestUrl,
    upstashRedisRestToken: argv.upstashRedisRestToken,
  };

  // Validate Upstash Redis options if using upstash-redis-rest.
  if (config.storage === 'upstash-redis-rest') {
    if (!config.upstashRedisRestUrl || !config.upstashRedisRestUrl.trim()) {
      logErr("Error: --upstashRedisRestUrl is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
    if (!config.upstashRedisRestToken || !config.upstashRedisRestToken.trim()) {
      logErr("Error: --upstashRedisRestToken is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
  }

  if (config.transport === 'stdio') {
    // For stdio, always run in memory-single mode.
    const memoryKey = "single";
    const server = createXServer(memoryKey, config);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log('Listening on stdio');
    return;
  }

  // For SSE transport:
  const app = express();

  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  // Parse JSON on all routes except /message.
  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: ExpressResponse) => {
    let memoryKey: string;
    if (config.storage === 'memory-single') {
      memoryKey = "single";
    } else {
      // For "memory" or "upstash-redis-rest", use the header named by storageHeaderKey.
      const headerVal = req.headers[config.storageHeaderKey!.toLowerCase()];
      if (typeof headerVal !== 'string' || !headerVal.trim()) {
        res.status(400).json({ error: `Missing or invalid "${config.storageHeaderKey}" header` });
        return;
      }
      memoryKey = headerVal.trim();
    }

    const server = createXServer(memoryKey, config);
    const transport = new SSEServerTransport('/message', res);
    await server.connect(transport);
    const sessionId = transport.sessionId;
    sessions.push({ memoryKey, server, transport, sessionId });
    log(`[${sessionId}] SSE connected for key: "${memoryKey}"`);
    transport.onclose = () => {
      log(`[${sessionId}] SSE connection closed`);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    req.on('close', () => {
      log(`[${sessionId}] Client disconnected`);
      sessions = sessions.filter(s => s.transport !== transport);
    });
  });

  app.post('/message', async (req: Request, res: ExpressResponse) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
      res.status(404).send({ error: 'No active session' });
      return;
    }
    try {
      await target.transport.handlePostMessage(req, res);
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err);
      res.status(500).send({ error: 'Internal error' });
    }
  });

  app.listen(config.port, () => {
    log(`Listening on port ${config.port} [storage=${config.storage}]`);
  });
}

main().catch(err => {
  logErr('Fatal error:', err);
  process.exit(1);
});
