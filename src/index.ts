#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import crypto from 'crypto'

// --------------------------------------------------------------------
// 1) Parse CLI options (including X credentials)
// --------------------------------------------------------------------
const argv = yargs(hideBin(process.argv))
  .option('port', { type: 'number', default: 8000 })
  .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
  .option('xClientId', { type: 'string', demandOption: true, describe: "X Client ID" })
  .option('xClientSecret', { type: 'string', demandOption: true, describe: "X Client Secret" })
  .option('xRedirectUri', { type: 'string', demandOption: true, describe: "X Redirect URI" })
  .help()
  .parseSync()

const log = (...args: any[]) => console.log('[x-mcp]', ...args)
const logErr = (...args: any[]) => console.error('[x-mcp]', ...args)

// --------------------------------------------------------------------
// 2) Global X Auth State and PKCE Variables
// --------------------------------------------------------------------
let xAccessToken: string | null = null
let xRefreshToken: string | null = null
let xUserId: string | null = null
let codeVerifier: string | null = null

// Generate PKCE code verifier and code challenge
function generatePKCECodes(): { codeVerifier: string; codeChallenge: string } {
  const randomBytes = crypto.randomBytes(32)
  const verifier = randomBytes
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
  const hash = crypto.createHash('sha256').update(verifier).digest()
  const challenge = hash
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
  return { codeVerifier: verifier, codeChallenge: challenge }
}

const pkce = generatePKCECodes()
codeVerifier = pkce.codeVerifier

// --------------------------------------------------------------------
// 3) X OAuth Setup (Authorization Code Flow with PKCE)
// --------------------------------------------------------------------
function generateXAuthUrl(): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: argv.xClientId,
    redirect_uri: argv.xRedirectUri,
    // Request tweet.read, users.read, tweet.write and offline.access for refresh token support.
    scope: 'tweet.read users.read tweet.write offline.access',
    state: 'state', // In production, use a random value to mitigate CSRF.
    code_challenge: pkce.codeChallenge,
    code_challenge_method: 'S256'
  })
  return `https://x.com/i/oauth2/authorize?${params.toString()}`
}

async function exchangeXAuthCode(code: string): Promise<string> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code.trim(),
    redirect_uri: argv.xRedirectUri,
    code_verifier: codeVerifier!
  })
  // Include client_id in the body if needed.
  params.append('client_id', argv.xClientId)

  // For confidential clients, send client credentials in the Authorization header.
  const basicAuth = Buffer.from(`${argv.xClientId}:${argv.xClientSecret}`).toString('base64')
  const response = await fetch('https://api.x.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`
    },
    body: params.toString()
  })
  const data = await response.json()
  if (!data.access_token) {
    throw new Error('Failed to obtain X access token.')
  }
  xAccessToken = data.access_token
  // Save the refresh token if issued.
  if (data.refresh_token) {
    xRefreshToken = data.refresh_token
  }
  return data.access_token
}

async function fetchXUser(): Promise<any> {
  if (!xAccessToken) throw new Error('No X access token available.')
  // Use auto-refresh helper to retry if unauthorized.
  const response = await autorefreshFetch('https://api.x.com/2/users/me', {
    headers: { 'Authorization': `Bearer ${xAccessToken}` }
  })
  const data = await response.json()
  if (!data.data || !data.data.id) {
    throw new Error('Failed to fetch X user id.')
  }
  xUserId = data.data.id
  return data.data
}

async function authX(args: { code: string }): Promise<any> {
  const { code } = args
  await exchangeXAuthCode(code)
  const user = await fetchXUser()
  return { success: true, provider: "x", user }
}

// --------------------------------------------------------------------
// 4) Automatic token refresh helper
// --------------------------------------------------------------------
async function autorefreshFetch(url: string, options: RequestInit) {
  let response = await fetch(url, options)
  if (response.status === 401) {
    try {
      await refreshXAccessToken()
      // Update the Authorization header with the new token and retry.
      if (options.headers && typeof options.headers === 'object' && !Array.isArray(options.headers)) {
        (options.headers as Record<string, string>)['Authorization'] = `Bearer ${xAccessToken}`
      } else {
        options.headers = { 'Authorization': `Bearer ${xAccessToken}` }
      }
      response = await fetch(url, options)
    } catch (err: any) {
      throw new Error("Token refresh failed: " + err.message)
    }
  }
  return response
}

// --------------------------------------------------------------------
// 5) Refresh Token Function
// --------------------------------------------------------------------
async function refreshXAccessToken(): Promise<string> {
  if (!xRefreshToken) throw new Error("No refresh token available.")
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: xRefreshToken,
    client_id: argv.xClientId
  })
  const basicAuth = Buffer.from(`${argv.xClientId}:${argv.xClientSecret}`).toString('base64')
  const response = await fetch('https://api.x.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`
    },
    body: params.toString()
  })
  const data = await response.json()
  if (!data.access_token) {
    throw new Error('Failed to refresh X access token.')
  }
  xAccessToken = data.access_token
  if (data.refresh_token) {
    xRefreshToken = data.refresh_token
  }
  return data.access_token
}

// --------------------------------------------------------------------
// 6) Tool Functions: X Tweet Creation, Retrieval, and Token Refresh
// --------------------------------------------------------------------
async function createXTweetTool(args: { tweetContent: string }): Promise<any> {
  if (!xAccessToken || !xUserId) {
    throw new Error('No X authentication configured. Run x_exchange_auth_code first.')
  }
  const { tweetContent } = args
  const postData = { text: tweetContent }
  const response = await autorefreshFetch('https://api.x.com/2/tweets', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${xAccessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(postData)
  })
  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`X tweet creation failed: ${errorText}`)
  }
  return { success: true, message: 'Tweet created successfully.' }
}

async function getXTweetsTool(args: { query: string }): Promise<any> {
  if (!xAccessToken) {
    throw new Error('No X authentication configured. Run x_exchange_auth_code first.')
  }
  const { query } = args
  const url = `https://api.x.com/2/tweets/search/recent?query=${encodeURIComponent(query)}`
  const response = await autorefreshFetch(url, {
    headers: { 'Authorization': `Bearer ${xAccessToken}` }
  })
  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`X get tweets failed: ${errorText}`)
  }
  const data = await response.json()
  return data
}

// --------------------------------------------------------------------
// 7) Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(data, null, 2)
      }
    ]
  }
}

// --------------------------------------------------------------------
// 8) Create the MCP server, registering our tools
// --------------------------------------------------------------------
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'X MCP Server',
    version: '1.0.0'
  })

  server.tool(
    'x_auth_url',
    'Return an OAuth URL for X (visit this URL to grant access with tweet.read, users.read, tweet.write, and offline.access scopes).',
    {},
    async () => {
      try {
        const authUrl = generateXAuthUrl()
        return toTextJson({ authUrl })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'x_exchange_auth_code',
    'Set up X authentication by exchanging an auth code.',
    { code: z.string() },
    async (args) => {
      try {
        const result = await authX(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'x_create_tweet',
    'Create a new tweet on X on behalf of the authenticated user. Provide tweetContent as text.',
    { tweetContent: z.string() },
    async (args) => {
      try {
        const result = await createXTweetTool(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'x_get_tweets',
    'Search for recent tweets on X. Provide a query string to search for tweets.',
    { query: z.string() },
    async (args) => {
      try {
        const result = await getXTweetsTool(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  return server
}

// --------------------------------------------------------------------
// 9) Minimal Fly.io "replay" handling (optional)
// --------------------------------------------------------------------
function saveMachineId(req: Request) {
  // Optional: Implement machine ID saving logic as needed.
}

// --------------------------------------------------------------------
// 10) Main: Start either SSE or stdio server
// --------------------------------------------------------------------
function main() {
  const server = createMcpServer()

  if (argv.transport === 'stdio') {
    const transport = new StdioServerTransport()
    void server.connect(transport)
    log('Listening on stdio')
    return
  }

  const port = argv.port
  const app = express()
  let sessions: { server: McpServer; transport: SSEServerTransport }[] = []

  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  app.get('/', async (req: Request, res: Response) => {
    saveMachineId(req)
    const transport = new SSEServerTransport('/message', res)
    const mcpInstance = createMcpServer()
    await mcpInstance.connect(transport)
    sessions.push({ server: mcpInstance, transport })

    const sessionId = transport.sessionId
    log(`[${sessionId}] SSE connection established`)

    transport.onclose = () => {
      log(`[${sessionId}] SSE closed`)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] SSE client disconnected`)
      sessions = sessions.filter(s => s.transport !== transport)
    })
  })

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      logErr('Missing sessionId')
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId)
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

  app.listen(port, () => {
    log(`Listening on port ${port} (${argv.transport})`)
  })
}

main()
