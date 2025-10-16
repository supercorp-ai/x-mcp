#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import cors from 'cors'
import type { CorsOptionsDelegate } from 'cors'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { InMemoryEventStore } from '@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js'
import { z } from 'zod'
import crypto from 'crypto'
import { Redis } from '@upstash/redis'

// Node 22+ provides global fetch, Blob, FormData

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }]
  }
}

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number
  transport: 'sse' | 'stdio' | 'http'
  httpMode: 'stateful' | 'stateless'
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest'
  xClientId: string
  xClientSecret: string
  xRedirectUri: string
  storageHeaderKey?: string
  upstashRedisRestUrl?: string
  upstashRedisRestToken?: string
}

interface Storage {
  get(memoryKey: string): Promise<{
    accessToken?: string
    refreshToken?: string
    userId?: string
    codeVerifier?: string
  } | undefined>
  set(
    memoryKey: string,
    data: {
      accessToken?: string
      refreshToken?: string
      userId?: string
      codeVerifier?: string
    }
  ): Promise<void>
}

// --------------------------------------------------------------------
// In-Memory Storage Implementation
// --------------------------------------------------------------------
class MemoryStorage implements Storage {
  private storage: Record<
    string,
    { accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string }
  > = {}

  async get(memoryKey: string) {
    return this.storage[memoryKey]
  }

  async set(
    memoryKey: string,
    data: { accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string }
  ) {
    this.storage[memoryKey] = { ...this.storage[memoryKey], ...data }
  }
}

// --------------------------------------------------------------------
// Upstash Redis Storage Implementation
// --------------------------------------------------------------------
class RedisStorage implements Storage {
  private redis: Redis
  private keyPrefix: string

  constructor(redisUrl: string, redisToken: string, keyPrefix: string) {
    this.redis = new Redis({ url: redisUrl, token: redisToken })
    this.keyPrefix = keyPrefix
  }

  async get(memoryKey: string): Promise<{
    accessToken?: string
    refreshToken?: string
    userId?: string
    codeVerifier?: string
  } | undefined> {
    const raw = await this.redis.get<string>(`${this.keyPrefix}:${memoryKey}`)
    if (raw == null) return undefined
    try {
      return typeof raw === 'string' ? (JSON.parse(raw) as any) : (raw as any)
    } catch {
      // If value was stored as object by Upstash JSON mode, just return it
      return raw as any
    }
  }

  async set(
    memoryKey: string,
    data: { accessToken?: string; refreshToken?: string; userId?: string; codeVerifier?: string }
  ) {
    const existing = (await this.get(memoryKey)) || {}
    const newData = { ...existing, ...data }
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(newData))
  }
}

// --------------------------------------------------------------------
// PKCE Code Generation for OAuth
// --------------------------------------------------------------------
function generatePKCECodes(): { codeVerifier: string; codeChallenge: string } {
  const randomBytes = crypto.randomBytes(32)
  const codeVerifier = randomBytes
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
  const hash = crypto.createHash('sha256').update(codeVerifier).digest()
  const codeChallenge = hash
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
  return { codeVerifier, codeChallenge }
}

// --------------------------------------------------------------------
// OAuth Helper Functions (using config)
// --------------------------------------------------------------------
function generateAuthUrl(config: Config, storage: Storage, memoryKey: string): string {
  const pkce = generatePKCECodes()
  // Save the code verifier for later use.
  storage.set(memoryKey, { codeVerifier: pkce.codeVerifier })
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.xClientId,
    redirect_uri: config.xRedirectUri,
    scope: 'tweet.read users.read tweet.write media.write offline.access',
    state: 'state',
    code_challenge: pkce.codeChallenge,
    code_challenge_method: 'S256'
  })
  return `https://x.com/i/oauth2/authorize?${params.toString()}`
}

async function exchangeAuthCode(
  code: string,
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<string> {
  const stored = await storage.get(memoryKey)
  if (!stored || !stored.codeVerifier) {
    throw new Error('No PKCE code verifier found. Generate auth URL first.')
  }
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code.trim(),
    redirect_uri: config.xRedirectUri,
    code_verifier: stored.codeVerifier
  })
  params.append('client_id', config.xClientId)
  const basicAuth = Buffer.from(`${config.xClientId}:${config.xClientSecret}`).toString('base64')
  const response = await fetch('https://api.x.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${basicAuth}`
    },
    body: params.toString()
  })
  const data = await response.json()
  if (!data.access_token) {
    console.dir({ data }, { depth: null })
    throw new Error('Failed to obtain X access token.')
  }
  await storage.set(memoryKey, { accessToken: data.access_token, refreshToken: data.refresh_token })
  return data.access_token
}

async function autorefreshFetch(
  url: string,
  options: RequestInit,
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<globalThis.Response> {
  let stored = await storage.get(memoryKey)
  if (!stored || !stored.accessToken) throw new Error('No X access token available.')
  if (!options.headers || typeof options.headers !== 'object') {
    options.headers = {}
  }
  ;(options.headers as Record<string, string>)['Authorization'] = `Bearer ${stored.accessToken}`
  let response = (await fetch(url, options)) as globalThis.Response
  if (response.status === 401) {
    try {
      await refreshAccessToken(config, storage, memoryKey)
      stored = await storage.get(memoryKey)
      ;(options.headers as Record<string, string>)['Authorization'] = `Bearer ${stored?.accessToken}`
      response = (await fetch(url, options)) as globalThis.Response
    } catch (err: any) {
      throw new Error('Token refresh failed: ' + err.message)
    }
  }
  return response
}

async function refreshAccessToken(config: Config, storage: Storage, memoryKey: string): Promise<string> {
  const stored = await storage.get(memoryKey)
  if (!stored || !stored.refreshToken) throw new Error('No refresh token available.')
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: stored.refreshToken,
    client_id: config.xClientId
  })
  const basicAuth = Buffer.from(`${config.xClientId}:${config.xClientSecret}`).toString('base64')
  const response = await fetch('https://api.x.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${basicAuth}`
    },
    body: params.toString()
  })
  const data = await response.json()
  if (!data.access_token) {
    throw new Error('Failed to refresh X access token.')
  }
  await storage.set(memoryKey, { accessToken: data.access_token, refreshToken: data.refresh_token })
  return data.access_token
}

async function fetchUser(config: Config, storage: Storage, memoryKey: string): Promise<any> {
  const response = await autorefreshFetch('https://api.x.com/2/users/me', {}, config, storage, memoryKey)
  const data = (await response.json()) as { data: { id: string } }
  if (!data.data || !data.data.id) {
    throw new Error('Failed to fetch X user id.')
  }
  await storage.set(memoryKey, { userId: data.data.id })
  return data.data
}

async function auth(args: { code: string; memoryKey: string; config: Config; storage: Storage }): Promise<any> {
  const { code, memoryKey, config, storage } = args
  await exchangeAuthCode(code, config, storage, memoryKey)
  const user = await fetchUser(config, storage, memoryKey)
  return { success: true, provider: 'x', user }
}

async function uploadMedia(
  mediaUrl: string,
  _config: Config,
  storage: Storage,
  memoryKey: string
): Promise<string> {
  log('Starting media upload for URL:', mediaUrl)

  // ───────────────────────────────────────────────────────────────────
  // Download the file we are about to upload
  // ───────────────────────────────────────────────────────────────────
  const mediaResponse = await fetch(mediaUrl)
  if (!mediaResponse.ok) {
    throw new Error(`Failed to download media from ${mediaUrl}: ${await mediaResponse.text()}`)
  }

  // Node 24 type-safe: use ArrayBuffer (or Uint8Array) instead of Buffer for Blob
  const mediaArrayBuffer = await mediaResponse.arrayBuffer()
  const totalBytes = mediaArrayBuffer.byteLength
  const mediaType = detectMediaType(mediaUrl)
  const mediaCategory = 'tweet_image' // unchanged

  // ───────────────────────────────────────────────────────────────────
  // 1. INITIALIZE
  // ───────────────────────────────────────────────────────────────────
  const initRes = await fetch('https://api.x.com/2/media/upload/initialize', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${(await storage.get(memoryKey))?.accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      media_type: mediaType,
      media_category: mediaCategory,
      total_bytes: totalBytes
    })
  })
  const initJson = await initRes.json()
  if (!initRes.ok || !initJson?.data?.id) {
    const msg = initJson?.errors?.[0]?.message ?? 'Unknown error'
    throw new Error(
      `Media upload INITIALIZE failed: ${msg}. Please reauthorize to use the new version of the X API be able to post images.`
    )
  }
  const mediaId = initJson.data.id
  log('INITIALIZE successful – media_id:', mediaId)

  // ───────────────────────────────────────────────────────────────────
  // 2. APPEND   (single chunk for images)
  // ───────────────────────────────────────────────────────────────────
  const appendUrl = `https://api.x.com/2/media/upload/${mediaId}/append`
  const blob = new Blob([mediaArrayBuffer], { type: mediaType }) // ← Node 24-safe
  const form = new FormData()
  form.append('segment_index', '0')
  form.append('media', blob, 'upload' + mediaType.replace('/', '.'))

  const appendRes = await fetch(appendUrl, {
    method: 'POST',
    headers: { Authorization: `Bearer ${(await storage.get(memoryKey))?.accessToken}` },
    body: form
  })
  if (!appendRes.ok && appendRes.status !== 204) {
    const appendJson = await appendRes.json().catch(() => ({}))
    const msg = (appendJson as any)?.errors?.[0]?.message ?? `HTTP ${appendRes.status}`
    throw new Error(`Media upload APPEND failed: ${msg}`)
  }
  log('APPEND successful.')

  // ───────────────────────────────────────────────────────────────────
  // 3. FINALIZE
  // ───────────────────────────────────────────────────────────────────
  const finalizeUrl = `https://api.x.com/2/media/upload/${mediaId}/finalize`
  const finalRes = await fetch(finalizeUrl, {
    method: 'POST',
    headers: { Authorization: `Bearer ${(await storage.get(memoryKey))?.accessToken}` }
  })
  const finalJson = await finalRes.json()
  if (!finalRes.ok || finalJson?.errors?.length) {
    const msg = finalJson?.errors?.[0]?.message ?? 'Unknown error'
    throw new Error(`Media upload FINALIZE failed: ${msg}`)
  }
  log('FINALIZE successful. Media ready:', mediaId)

  return mediaId // ← returned exactly as before
}

/**
 * Helper to detect media MIME type from the file extension of the URL.
 */
function detectMediaType(mediaUrl: string): string {
  const lower = mediaUrl.toLowerCase()
  if (lower.endsWith('.webp')) return 'image/webp'
  if (lower.endsWith('.png')) return 'image/png'
  if (lower.endsWith('.gif')) return 'image/gif'
  return 'image/jpeg'
}

// --------------------------------------------------------------------
// Tweet Tools
// --------------------------------------------------------------------
async function createTweetTool(args: {
  tweetContent: string
  mediaUrl?: string
  inReplyToTweetId?: string
  memoryKey: string
  config: Config
  storage: Storage
}): Promise<any> {
  const { tweetContent, mediaUrl, inReplyToTweetId, memoryKey, config, storage } = args
  const stored = await storage.get(memoryKey)
  if (!stored || !stored.accessToken || !stored.userId) {
    throw new Error(
      `No X authentication configured for key "${memoryKey}". Run x_exchange_auth_code first.`
    )
  }
  const postData: any = { text: tweetContent }
  if (inReplyToTweetId) {
    postData.reply = { in_reply_to_tweet_id: inReplyToTweetId }
  }
  if (mediaUrl && mediaUrl.trim()) {
    const mediaId = await uploadMedia(mediaUrl, config, storage, memoryKey)
    postData.media = { media_ids: [mediaId] }
  }
  const response = await autorefreshFetch(
    'https://api.x.com/2/tweets',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(postData)
    },
    config,
    storage,
    memoryKey
  )
  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`X tweet creation failed: ${errorText}`)
  }
  const result = await response.json()
  return { success: true, message: 'Tweet created successfully.', result }
}

async function getTweetsTool(args: {
  query: string
  memoryKey: string
  config: Config
  storage: Storage
}): Promise<any> {
  const { query, memoryKey, config, storage } = args
  const url = `https://api.x.com/2/tweets/search/recent?query=${encodeURIComponent(query)}`
  const response = await autorefreshFetch(url, {}, config, storage, memoryKey)
  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`X get tweets failed: ${errorText}`)
  }
  const data = await response.json()
  return data
}

// --------------------------------------------------------------------
// MCP Server Creation: Register X Tools with Configurable Prefix
// --------------------------------------------------------------------
function createXServer(memoryKey: string, config: Config, toolsPrefix: string): McpServer {
  let storage: Storage
  if (config.storage === 'upstash-redis-rest') {
    storage = new RedisStorage(
      config.upstashRedisRestUrl!,
      config.upstashRedisRestToken!,
      config.storageHeaderKey!
    )
  } else {
    storage = new MemoryStorage()
  }
  const server = new McpServer({
    name: `X MCP Server (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  })

  server.tool(
    `${toolsPrefix}auth_url`,
    'Return an OAuth URL for X (visit this URL to grant access with tweet.read, users.read, tweet.write, and offline.access scopes).',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional()
    },
    async () => {
      try {
        const authUrl = generateAuthUrl(config, storage, memoryKey)
        return toTextJson({ authUrl })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    `${toolsPrefix}exchange_auth_code`,
    'Set up X authentication by exchanging an auth code.',
    { code: z.string() },
    async (args) => {
      try {
        const result = await auth({ code: args.code, memoryKey, config, storage })
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

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
        const result = await createTweetTool({
          tweetContent: args.tweetContent,
          mediaUrl: args.mediaUrl,
          inReplyToTweetId: args.inReplyToTweetId,
          memoryKey,
          config,
          storage
        })
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    `${toolsPrefix}get_tweets`,
    'Search for recent tweets on X. Provide a query string to search for tweets.',
    { query: z.string() },
    async (args: { query: string }) => {
      try {
        const result = await getTweetsTool({ query: args.query, memoryKey, config, storage })
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  return server
}

// --------------------------------------------------------------------
// Logging Helpers
// --------------------------------------------------------------------
function log(...args: any[]) {
  console.log('[x-mcp]', ...args)
}

function logErr(...args: any[]) {
  console.error('[x-mcp]', ...args)
}

// --------------------------------------------------------------------
// Main: Start the server
// --------------------------------------------------------------------
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio', 'http'], default: 'sse' })
    .option('httpMode', {
      type: 'string',
      choices: ['stateful', 'stateless'] as const,
      default: 'stateful',
      describe:
        'Choose HTTP session mode when --transport=http. "stateful" uses MCP session IDs; "stateless" treats each request separately.'
    })
    .option('storage', {
      type: 'string',
      choices: ['memory-single', 'memory', 'upstash-redis-rest'],
      default: 'memory-single',
      describe:
        'Choose storage backend: "memory-single" uses fixed single-user storage; "memory" uses multi-user in-memory storage (requires --storageHeaderKey); "upstash-redis-rest" uses Upstash Redis (requires --storageHeaderKey, --upstashRedisRestUrl, and --upstashRedisRestToken).'
    })
    .option('xClientId', { type: 'string', demandOption: true, describe: 'X Client ID' })
    .option('xClientSecret', { type: 'string', demandOption: true, describe: 'X Client Secret' })
    .option('xRedirectUri', { type: 'string', demandOption: true, describe: 'X Redirect URI' })
    .option('storageHeaderKey', {
      type: 'string',
      describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.'
    })
    .option('upstashRedisRestUrl', {
      type: 'string',
      describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)'
    })
    .option('upstashRedisRestToken', {
      type: 'string',
      describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)'
    })
    .option('toolsPrefix', { type: 'string', default: 'x_', describe: 'Prefix to add to all tool names.' })
    .help()
    .parseSync()

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio' | 'http',
    httpMode: (argv.httpMode as 'stateful' | 'stateless') || 'stateful',
    storage: argv.storage as 'memory-single' | 'memory' | 'upstash-redis-rest',
    xClientId: argv.xClientId,
    xClientSecret: argv.xClientSecret,
    xRedirectUri: argv.xRedirectUri,
    storageHeaderKey:
      argv.storage === 'memory-single'
        ? undefined
        : argv.storageHeaderKey && argv.storageHeaderKey.trim()
          ? argv.storageHeaderKey.trim()
          : (() => {
              logErr(
                'Error: --storageHeaderKey is required for storage modes "memory" or "upstash-redis-rest".'
              )
              process.exit(1)
              return ''
            })(),
    upstashRedisRestUrl: argv.upstashRedisRestUrl,
    upstashRedisRestToken: argv.upstashRedisRestToken
  }

  if (config.storage === 'upstash-redis-rest') {
    if (!config.upstashRedisRestUrl || !config.upstashRedisRestUrl.trim()) {
      logErr("Error: --upstashRedisRestUrl is required for storage mode 'upstash-redis-rest'.")
      process.exit(1)
    }
    if (!config.upstashRedisRestToken || !config.upstashRedisRestToken.trim()) {
      logErr("Error: --upstashRedisRestToken is required for storage mode 'upstash-redis-rest'.")
      process.exit(1)
    }
  }

  const storageHeaderKeyLower = config.storageHeaderKey?.toLowerCase()
  const corsBaseHeaders = [
    'Content-Type',
    'Accept',
    'Mcp-Session-Id',
    'mcp-session-id',
    config.storageHeaderKey,
    storageHeaderKeyLower
  ].filter((header): header is string => typeof header === 'string' && header.length > 0)
  const corsOptionsDelegate: CorsOptionsDelegate<Request> = (req, callback) => {
    const headers = new Set<string>(corsBaseHeaders)
    const requestHeaders = req.header('Access-Control-Request-Headers')
    if (requestHeaders) {
      for (const header of requestHeaders.split(',')) {
        const trimmed = header.trim()
        if (trimmed) headers.add(trimmed)
      }
    }
    callback(null, {
      origin: true,
      allowedHeaders: Array.from(headers),
      exposedHeaders: ['Mcp-Session-Id']
    })
  }
  const corsMiddleware = cors(corsOptionsDelegate)

  const resolveMemoryKeyFromHeaders = (headers: Request['headers']): string | undefined => {
    if (config.storage === 'memory-single') return 'single'
    const keyName = storageHeaderKeyLower
    if (!keyName) return undefined
    const raw = headers[keyName]
    if (typeof raw === 'string') {
      const trimmed = raw.trim()
      return trimmed.length > 0 ? trimmed : undefined
    }
    if (Array.isArray(raw)) {
      for (const value of raw) {
        if (typeof value === 'string') {
          const trimmed = value.trim()
          if (trimmed.length > 0) {
            return trimmed
          }
        }
      }
    }
    return undefined
  }

  const describeMemoryKey = (memoryKey: string) =>
    config.storage === 'memory-single' || !config.storageHeaderKey
      ? `"${memoryKey}"`
      : `${config.storageHeaderKey}="${memoryKey}"`

  const toolsPrefix: string = argv.toolsPrefix

  if (config.transport === 'stdio') {
    const memoryKey = 'single'
    const server = createXServer(memoryKey, config, toolsPrefix)
    const transport = new StdioServerTransport()
    await server.connect(transport)
    log('Listening on stdio')
    return
  }

  // ───────────────────────────────────────────────────────────────────
  // Streamable HTTP transport at root "/"
  // ───────────────────────────────────────────────────────────────────
  if (config.transport === 'http') {
    const httpMode = config.httpMode
    const isStatefulHttp = httpMode === 'stateful'
    const app = express()

    app.use(corsMiddleware)
    app.options('*', corsMiddleware)

    if (isStatefulHttp) {
      app.use((req, res, next) => {
        if (req.path === '/') return next()
        return express.json()(req, res, next)
      })
    } else {
      app.use(express.json())
    }

    function createServerFor(memoryKey: string) {
      return createXServer(memoryKey, config, toolsPrefix)
    }

    if (isStatefulHttp) {
      interface HttpSession {
        memoryKey: string
        server: McpServer
        transport: StreamableHTTPServerTransport
      }
      const sessions = new Map<string, HttpSession>()
      const eventStore = new InMemoryEventStore()

      app.post('/', async (req: Request, res: ExpressResponse) => {
        try {
          const sessionId = req.headers['mcp-session-id'] as string | undefined

          if (sessionId && sessions.has(sessionId)) {
            const { transport } = sessions.get(sessionId)!
            await transport.handleRequest(req, res)
            return
          }

          const memoryKey = resolveMemoryKeyFromHeaders(req.headers)
          if (!memoryKey) {
            res.status(400).json({
              jsonrpc: '2.0',
              error: {
                code: -32000,
                message: config.storageHeaderKey
                  ? `Bad Request: Missing or invalid "${config.storageHeaderKey}" header`
                  : 'Bad Request: Missing required storage identifier'
              },
              id: (req as any)?.body?.id
            })
            return
          }

          const server = createServerFor(memoryKey)

          let transport!: StreamableHTTPServerTransport
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => crypto.randomUUID(),
            eventStore,
            onsessioninitialized: (newSessionId: string) => {
              sessions.set(newSessionId, { memoryKey, server, transport })
              log(`[${newSessionId}] HTTP session initialized for ${describeMemoryKey(memoryKey)}`)
            }
          })

          transport.onclose = async () => {
            const sid = transport.sessionId
            if (sid && sessions.has(sid)) {
              sessions.delete(sid)
              log(`[${sid}] Transport closed; removed session`)
            }
            try {
              await server.close()
            } catch {
              // already closed
            }
          }

          await server.connect(transport)
          await transport.handleRequest(req, res)
        } catch (err) {
          logErr('Error handling HTTP POST /:', err)
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id
            })
          }
        }
      })

      app.get('/', async (req: Request, res: ExpressResponse) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined
        if (!sessionId || !sessions.has(sessionId)) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
            id: (req as any)?.body?.id
          })
          return
        }
        try {
          const { transport } = sessions.get(sessionId)!
          await transport.handleRequest(req, res)
        } catch (err) {
          logErr(`[${sessionId}] Error handling HTTP GET /:`, err)
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id
            })
          }
        }
      })

      app.delete('/', async (req: Request, res: ExpressResponse) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined
        if (!sessionId || !sessions.has(sessionId)) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
            id: (req as any)?.body?.id
          })
          return
        }
        try {
          const { transport } = sessions.get(sessionId)!
          await transport.handleRequest(req, res)
        } catch (err) {
          logErr(`[${sessionId}] Error handling HTTP DELETE /:`, err)
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Error handling session termination' },
              id: (req as any)?.body?.id
            })
          }
        }
      })
    } else {
      interface StatelessSession {
        memoryKey: string
        server: McpServer
        transport: StreamableHTTPServerTransport
      }

      const statelessSessions = new Map<string, StatelessSession>()
      const statelessSessionPromises = new Map<string, Promise<StatelessSession>>()

      const destroyStatelessSession = async (memoryKey: string) => {
        const session = statelessSessions.get(memoryKey)
        if (!session) return
        statelessSessions.delete(memoryKey)
        statelessSessionPromises.delete(memoryKey)
        try {
          await session.transport.close()
        } catch (err) {
          logErr(`[stateless:${memoryKey}] Error closing transport:`, err)
        }
        try {
          await session.server.close()
        } catch (err) {
          logErr(`[stateless:${memoryKey}] Error closing server:`, err)
        }
      }

      const getOrCreateStatelessSession = async (memoryKey: string): Promise<StatelessSession> => {
        const existing = statelessSessions.get(memoryKey)
        if (existing) {
          return existing
        }

        const pending = statelessSessionPromises.get(memoryKey)
        if (pending) {
          return pending
        }

        const creation = (async () => {
          const server = createServerFor(memoryKey)
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined
          })
          transport.onerror = (error) => {
            logErr(`[stateless:${memoryKey}] Streamable HTTP transport error:`, error)
          }
          transport.onclose = async () => {
            statelessSessions.delete(memoryKey)
            statelessSessionPromises.delete(memoryKey)
            try {
              await server.close()
            } catch (err) {
              logErr(`[stateless:${memoryKey}] Error closing server on transport close:`, err)
            }
          }
          await server.connect(transport)
          const session: StatelessSession = { memoryKey, server, transport }
          statelessSessions.set(memoryKey, session)
          return session
        })()
          .catch((err) => {
            statelessSessionPromises.delete(memoryKey)
            throw err
          })
          .finally(() => {
            statelessSessionPromises.delete(memoryKey)
          })

        statelessSessionPromises.set(memoryKey, creation)
        return creation
      }

      const handleStatelessRequest = async (
        req: Request,
        res: ExpressResponse,
        handler: (session: StatelessSession, memoryKey: string) => Promise<void>
      ) => {
        const memoryKey = resolveMemoryKeyFromHeaders(req.headers)
        if (!memoryKey) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: config.storageHeaderKey
                ? `Bad Request: Missing or invalid "${config.storageHeaderKey}" header`
                : 'Bad Request: Missing required storage identifier'
            },
            id: (req as any)?.body?.id ?? null
          })
          return
        }

        try {
          const session = await getOrCreateStatelessSession(memoryKey)
          await handler(session, memoryKey)
        } catch (err) {
          logErr('Error handling HTTP request (stateless):', err)
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id ?? null
            })
          }
        }
      }

      app.post('/', async (req: Request, res: ExpressResponse) => {
        await handleStatelessRequest(req, res, async ({ transport }, memoryKey) => {
          res.on('close', () => {
            if (!res.writableEnded) {
              logErr(`[stateless:${memoryKey}] POST connection closed prematurely; destroying session`)
              void destroyStatelessSession(memoryKey)
            }
          })

          await transport.handleRequest(req, res, req.body)
        })
      })

      app.get('/', async (req: Request, res: ExpressResponse) => {
        await handleStatelessRequest(req, res, async ({ transport }) => {
          await transport.handleRequest(req, res)
        })
      })

      app.delete('/', async (req: Request, res: ExpressResponse) => {
        await handleStatelessRequest(req, res, async ({ transport }, memoryKey) => {
          try {
            await transport.handleRequest(req, res)
          } finally {
            void destroyStatelessSession(memoryKey)
          }
        })
      })
    }

    app.listen(config.port, () => {
      log(`Listening on port ${config.port} (http:${httpMode}) [storage=${config.storage}]`)
    })

    return // prevent falling through to SSE setup
  }

  // ───────────────────────────────────────────────────────────────────
  // SSE transport (existing behavior)
  // ───────────────────────────────────────────────────────────────────
  const app = express()
  interface ServerSession {
    memoryKey: string
    server: McpServer
    transport: SSEServerTransport
    sessionId: string
  }
  let sessions: ServerSession[] = []

  app.use(corsMiddleware)
  app.options('*', corsMiddleware)

  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  app.get('/', async (req: Request, res: ExpressResponse) => {
    const memoryKey = resolveMemoryKeyFromHeaders(req.headers)
    if (!memoryKey) {
      const message = config.storageHeaderKey
        ? `Missing or invalid "${config.storageHeaderKey}" header`
        : 'Missing required storage identifier'
      res.status(400).json({ error: message })
      return
    }
    const server = createXServer(memoryKey, config, toolsPrefix)
    const transport = new SSEServerTransport('/message', res)
    await server.connect(transport)
    const sessionId = transport.sessionId
    sessions.push({ memoryKey, server, transport, sessionId })
    log(`[${sessionId}] SSE connected for ${describeMemoryKey(memoryKey)}`)
    transport.onclose = () => {
      log(`[${sessionId}] SSE connection closed`)
      sessions = sessions.filter((s) => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter((s) => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] Client disconnected`)
      sessions = sessions.filter((s) => s.transport !== transport)
    })
  })

  app.post('/message', async (req: Request, res: ExpressResponse) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      logErr('Missing sessionId')
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find((s) => s.sessionId === sessionId)
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`)
      res.status(404).send({ error: 'No active session' })
      return
    }
    try {
      await target.transport.handlePostMessage(req, res)
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err)
      res.status(500).send({ error: 'Internal error' })
    }
  })

  app.listen(config.port, () => {
    const headerInfo =
      config.storage === 'memory-single'
        ? 'memory-single mode'
        : `header "${config.storageHeaderKey}"`
    log(`Listening on port ${config.port} (sse) [storage=${config.storage}] using ${headerInfo}`)
  })
}

main().catch((err: any) => {
  logErr('Fatal error:', err)
  process.exit(1)
})
