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

// Use Node 22 built-in fetch and FormData
// (No need to import node-fetch)

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      { type: 'text', text: JSON.stringify(data, null, 2) }
    ]
  };
}

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio';
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  xClientId: string;
  xClientSecret: string;
  xRedirectUri: string;
  storageHeaderKey?: string;
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
    const data = await this.redis.get(`${this.keyPrefix}:${memoryKey}`);
    return data === null ? undefined : data;
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
    scope: 'tweet.read users.read tweet.write media.write offline.access',
    state: 'state',
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
    console.dir({ data }, { depth: null });
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

async function uploadMedia(mediaUrl: string, config: Config, storage: Storage, memoryKey: string): Promise<string> {
  log("Starting media upload for URL:", mediaUrl);

  // Step 0: Download media as ArrayBuffer.
  log("Downloading media...");
  const mediaResponse = await fetch(mediaUrl);
  if (!mediaResponse.ok) {
    const errText = await mediaResponse.text();
    logErr("Error downloading media:", errText);
    throw new Error('Failed to download media from provided URL.');
  }
  const mediaBuffer = await mediaResponse.arrayBuffer();
  const totalBytes = Buffer.byteLength(Buffer.from(mediaBuffer));
  log("Downloaded media. Total bytes:", totalBytes);

  // Detect media type based on file extension.
  const mediaType = detectMediaType(mediaUrl);
  log("Detected media type:", mediaType);
  const mediaCategory = 'tweet_image';

  // Step 1: INIT
  const initParams = new URLSearchParams({
    command: 'INIT',
    total_bytes: totalBytes.toString(),
    media_type: mediaType,
    media_category: mediaCategory
  });
  log("INIT step - parameters:", initParams.toString());
  const initResponse = await fetch('https://api.x.com/2/media/upload', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Bearer ${(await storage.get(memoryKey))?.accessToken}`
    },
    body: initParams.toString()
  });
  log("INIT response status:", initResponse.status);
  const initRaw = await initResponse.text();
  log("INIT raw response:", initRaw);
  let initData: any;
  try {
    initData = JSON.parse(initRaw);
  } catch (e) {
    throw new Error(`Media upload INIT failed: Unable to parse response JSON. Raw response: ${initRaw}`);
  }
  if (!initResponse.ok || initData.errors) {
    let errMsg = initData.errors ? initData.errors[0].message : 'Unknown error';
    if (initResponse.status === 401) {
      errMsg = 'Unauthorized: invalid or expired token';
    } else if (initResponse.status === 403) {
      errMsg = 'Forbidden: token does not have permission for media upload';
    }
    throw new Error(`Media upload INIT failed: ${errMsg}`);
  }
  const mediaId = initData.data.id;
  log("INIT successful. Media ID received:", mediaId);

  // Step 2: APPEND – Wrap the media buffer into a Blob.
  const blob = new Blob([Buffer.from(mediaBuffer)], { type: mediaType });
  const form = new FormData();
  form.append('command', 'APPEND');
  form.append('media_id', mediaId);
  form.append('segment_index', '0');
  form.append('media', blob, 'media.jpg'); // Pass filename only
  log("APPEND step - sending form data.");
  const appendResponse = await fetch('https://api.x.com/2/media/upload', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${(await storage.get(memoryKey))?.accessToken}`
    },
    body: form
  });
  log("APPEND response status:", appendResponse.status);
  if (appendResponse.status === 204) {
    log("APPEND returned 204: no content, treating as success.");
  } else {
    const appendRaw = await appendResponse.text();
    log("APPEND raw response:", appendRaw);
    let appendData: any;
    try {
      appendData = JSON.parse(appendRaw);
    } catch (e) {
      throw new Error(`Media upload APPEND failed: Unable to parse response JSON. Raw response: ${appendRaw}`);
    }
    if (!appendResponse.ok || appendData.errors) {
      let errMsg = appendData.errors ? appendData.errors[0].message : 'Unknown error';
      if (appendResponse.status === 401) {
        errMsg = 'Unauthorized: invalid or expired token';
      } else if (appendResponse.status === 403) {
        errMsg = 'Forbidden: token does not have permission for media upload';
      }
      throw new Error(`Media upload APPEND failed: ${errMsg}`);
    }
  }

  // Step 3: FINALIZE
  const finalizeParams = new URLSearchParams({
    command: 'FINALIZE',
    media_id: mediaId
  });
  log("FINALIZE step - parameters:", finalizeParams.toString());
  const finalizeResponse = await fetch('https://api.x.com/2/media/upload', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Bearer ${(await storage.get(memoryKey))?.accessToken}`
    },
    body: finalizeParams.toString()
  });
  log("FINALIZE response status:", finalizeResponse.status);
  const finalizeRaw = await finalizeResponse.text();
  log("FINALIZE raw response:", finalizeRaw);
  let finalizeData: any;
  try {
    finalizeData = JSON.parse(finalizeRaw);
  } catch (e) {
    throw new Error(`Media upload FINALIZE failed: Unable to parse response JSON. Raw response: ${finalizeRaw}`);
  }
  if (!finalizeResponse.ok || finalizeData.errors) {
    let errMsg = finalizeData.errors ? finalizeData.errors[0].message : 'Unknown error';
    if (finalizeResponse.status === 401) {
      errMsg = 'Unauthorized: invalid or expired token';
    } else if (finalizeResponse.status === 403) {
      errMsg = 'Forbidden: token does not have permission for media upload';
    }
    throw new Error(`Media upload FINALIZE failed: ${errMsg}`);
  }
  log("FINALIZE successful. Media uploaded with ID:", mediaId);
  return mediaId;
}

/**
 * Helper to detect media MIME type from the file extension of the URL.
 */
function detectMediaType(mediaUrl: string): string {
  const lower = mediaUrl.toLowerCase();
  if (lower.endsWith('.webp')) return 'image/webp';
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.gif')) return 'image/gif';
  return 'image/jpeg';
}

// --------------------------------------------------------------------
// Modified Tweet Creation Tool: supports optional media upload and replying
// --------------------------------------------------------------------
async function createTweetTool(args: { tweetContent: string; mediaUrl?: string; inReplyToTweetId?: string; memoryKey: string; config: Config; storage: Storage }): Promise<any> {
  const { tweetContent, mediaUrl, inReplyToTweetId, memoryKey, config, storage } = args;
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken || !stored.userId) {
    throw new Error(`No X authentication configured for key "${memoryKey}". Run x_exchange_auth_code first.`);
  }
  const postData: any = { text: tweetContent };
  if (inReplyToTweetId) {
    postData.reply = { in_reply_to_tweet_id: inReplyToTweetId };
  }
  if (mediaUrl && mediaUrl.trim()) {
    const mediaId = await uploadMedia(mediaUrl, config, storage, memoryKey);
    postData.media = { media_ids: [mediaId] };
  }
  const response = await autorefreshFetch('https://api.x.com/2/tweets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(postData)
  }, config, storage, memoryKey);
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`X tweet creation failed: ${errorText}`);
  }
  const result = await response.json();
  return { success: true, message: 'Tweet created successfully.', result };
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
// MCP Server Creation: Register X Tools with Configurable Prefix
// --------------------------------------------------------------------
function createXServer(memoryKey: string, config: Config, toolsPrefix: string): McpServer {
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
    `${toolsPrefix}auth_url`,
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
    `${toolsPrefix}exchange_auth_code`,
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
    `${toolsPrefix}create_tweet`,
    'Create a new tweet on X. Provide tweetContent as text. Optionally, provide mediaUrl to upload an image and inReplyToTweetId to reply to a tweet.',
    {
      tweetContent: z.string().min(1).max(280),
      mediaUrl: z.string().optional(),
      inReplyToTweetId: z.string().optional()
    },
    async (args: { tweetContent: string; mediaUrl?: string; inReplyToTweetId?: string }) => {
      try {
        const result = await createTweetTool({ tweetContent: args.tweetContent, mediaUrl: args.mediaUrl, inReplyToTweetId: args.inReplyToTweetId, memoryKey, config, storage });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}get_tweets`,
    'Search for recent tweets on X. Provide a query string to search for tweets.',
    { query: z.string() },
    async (args: { query: string }) => {
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
    .option('toolsPrefix', { type: 'string', default: 'x_', describe: 'Prefix to add to all tool names.' })
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

  const toolsPrefix: string = argv.toolsPrefix;

  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createXServer(memoryKey, config, toolsPrefix);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log('Listening on stdio');
    return;
  }

  const app = express();
  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: ExpressResponse) => {
    let memoryKey: string;
    if ((argv.storage as string) === 'memory-single') {
      memoryKey = "single";
    } else {
      const headerVal = req.headers[(argv.storageHeaderKey as string).toLowerCase()];
      if (typeof headerVal !== 'string' || !headerVal.trim()) {
        res.status(400).json({ error: `Missing or invalid "${argv.storageHeaderKey}" header` });
        return;
      }
      memoryKey = headerVal.trim();
    }
    const server = createXServer(memoryKey, config, toolsPrefix);
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
      logErr('Missing sessionId');
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`);
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

  app.listen(argv.port, () => {
    log(`Listening on port ${argv.port} (${argv.transport})`);
  });
}

main().catch((err: any) => {
  logErr('Fatal error:', err);
  process.exit(1);
});
