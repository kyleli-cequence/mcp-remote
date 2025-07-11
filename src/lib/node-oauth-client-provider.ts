import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { getServerUrlHash, log, debugLog, DEBUG, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'

/**
 * Extended OAuthTokens interface that includes absolute expiration time
 */
interface ExtendedOAuthTokens extends OAuthTokens {
  expires_at?: number // Absolute timestamp when the token expires
}

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull
  private authorizeResource: string | undefined
  private _state: string

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = getServerUrlHash(options.serverUrl)
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this.authorizeResource = options.authorizeResource
    this._state = randomUUID()
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`
  }

  get clientMetadata() {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
    }
  }

  state(): string {
    return this._state
  }

  /**
   * Gets the client information for token refresh operations
   * @returns The client information or throws an error if not available
   */
  private async getClientInformationForRefresh(): Promise<OAuthClientInformationFull> {
    const clientInfo = await this.clientInformation()
    if (!clientInfo) {
      throw new Error('No client information available for token refresh')
    }
    return clientInfo
  }

  /**
   * Refreshes an access token using a refresh token
   * @param refreshToken The refresh token to use
   * @returns The new OAuth tokens
   */
  private async refreshAccessToken(refreshToken: string): Promise<OAuthTokens> {
    if (DEBUG) debugLog('Attempting to refresh access token')

    const clientInfo = await this.getClientInformationForRefresh()

    // For now, we'll construct the token endpoint based on the server URL
    // This is a simplified approach - ideally we'd get this from OAuth discovery
    const serverUrl = new URL(this.options.serverUrl)
    const tokenEndpoint = `${serverUrl.protocol}//${serverUrl.host}/oauth/token`

    const requestBody = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientInfo.client_id,
    })

    // Add client_secret if available (for confidential clients)
    if (clientInfo.client_secret) {
      requestBody.append('client_secret', clientInfo.client_secret)
    }

    if (DEBUG) debugLog('Making token refresh request', { tokenEndpoint, clientId: clientInfo.client_id })

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: requestBody,
    })

    if (!response.ok) {
      const errorText = await response.text()
      if (DEBUG) debugLog('Token refresh failed', { status: response.status, error: errorText })
      throw new Error(`Token refresh failed: HTTP ${response.status} - ${errorText}`)
    }

    const tokenData = await response.json()

    if (DEBUG)
      debugLog('Token refresh successful', {
        hasAccessToken: !!tokenData.access_token,
        hasRefreshToken: !!tokenData.refresh_token,
        expiresIn: tokenData.expires_in,
      })

    // Create new tokens object with absolute expiration time
    const newTokens: OAuthTokens = {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token || refreshToken, // Use new refresh token if provided, otherwise keep the old one
      expires_in: tokenData.expires_in,
      token_type: tokenData.token_type || 'Bearer',
      scope: tokenData.scope,
    }

    return newTokens
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    if (DEBUG) debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      if (DEBUG) debugLog('Returning static client info')
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )
    if (DEBUG) debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    if (DEBUG) debugLog('Saving client info', { client_id: clientInformation.client_id })
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    if (DEBUG) {
      debugLog('Reading OAuth tokens')
      debugLog('Token request stack trace:', new Error().stack)
    }

    const extendedTokens = await readJsonFile<ExtendedOAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)

    if (!extendedTokens) {
      if (DEBUG) debugLog('Token result: Not found')
      return undefined
    }

    // Check if token is expired (with 5 minute buffer)
    const REFRESH_BUFFER = 5 * 60 * 1000 // 5 minutes in milliseconds
    const now = Date.now()
    let isExpired = false

    if (extendedTokens.expires_at) {
      // Use absolute timestamp if available
      isExpired = now >= extendedTokens.expires_at - REFRESH_BUFFER
    } else if (extendedTokens.expires_in) {
      // Fallback to expires_in if no absolute timestamp
      isExpired = extendedTokens.expires_in <= 300 // 5 minutes
    }

    if (DEBUG) {
      const timeLeft = extendedTokens.expires_at ? Math.max(0, extendedTokens.expires_at - now) / 1000 : extendedTokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof extendedTokens.expires_in !== 'number' || extendedTokens.expires_in < 0) {
        debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
          expiresIn: extendedTokens.expires_in,
          tokenObject: JSON.stringify(extendedTokens),
          stack: new Error('Invalid expires_in value').stack,
        })
      }

      debugLog('Token result:', {
        found: true,
        hasAccessToken: !!extendedTokens.access_token,
        hasRefreshToken: !!extendedTokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        isExpired: isExpired,
        expiresInValue: extendedTokens.expires_in,
        expiresAt: extendedTokens.expires_at ? new Date(extendedTokens.expires_at).toISOString() : undefined,
      })
    }

    // If token is expired and we have a refresh token, try to refresh
    if (isExpired && extendedTokens.refresh_token) {
      if (DEBUG) debugLog('Token is expired, attempting refresh')

      try {
        const refreshedTokens = await this.refreshAccessToken(extendedTokens.refresh_token)
        await this.saveTokens(refreshedTokens)

        if (DEBUG) debugLog('Token refresh successful, returning refreshed tokens')
        return refreshedTokens
      } catch (error) {
        if (DEBUG)
          debugLog('Token refresh failed, returning undefined to trigger full re-auth', {
            error: error instanceof Error ? error.message : String(error),
          })
        log('Token refresh failed, will need to re-authenticate:', error instanceof Error ? error.message : String(error))
        return undefined
      }
    }

    // Return the original tokens (converted back to OAuthTokens interface)
    // Update expires_in to be the remaining time until expiration
    let remainingExpiresIn = extendedTokens.expires_in
    if (extendedTokens.expires_at) {
      remainingExpiresIn = Math.max(0, Math.floor((extendedTokens.expires_at - now) / 1000))
    }

    const tokens: OAuthTokens = {
      access_token: extendedTokens.access_token,
      refresh_token: extendedTokens.refresh_token,
      expires_in: remainingExpiresIn,
      token_type: extendedTokens.token_type,
      scope: extendedTokens.scope,
    }

    return tokens
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    // Convert expires_in to absolute timestamp
    const now = Date.now()
    const expiresAt = tokens.expires_in ? now + tokens.expires_in * 1000 : undefined

    const extendedTokens: ExtendedOAuthTokens = {
      ...tokens,
      expires_at: expiresAt,
    }

    if (DEBUG) {
      const timeLeft = tokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
        debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error('Invalid expires_in value').stack,
        })
      }

      debugLog('Saving tokens', {
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        expiresInValue: tokens.expires_in,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
      })
    }

    await writeJsonFile(this.serverUrlHash, 'tokens.json', extendedTokens)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    if (this.authorizeResource) {
      authorizationUrl.searchParams.set('resource', this.authorizeResource)
    }

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    if (DEBUG) debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      if (DEBUG) debugLog('Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    if (DEBUG) debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    if (DEBUG) debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    if (DEBUG) debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    if (DEBUG) debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        if (DEBUG) debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        if (DEBUG) debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        if (DEBUG) debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, 'code_verifier.txt')
        if (DEBUG) debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
