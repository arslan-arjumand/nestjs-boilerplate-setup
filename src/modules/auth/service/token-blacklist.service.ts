import { Injectable, OnModuleInit } from "@nestjs/common"
import { JwtService } from "@nestjs/jwt"
import config from "@/config"

@Injectable()
export class TokenBlacklistService implements OnModuleInit {
  private blacklistedTokens = new Map<string, Date>()
  private userActiveTokens = new Map<string, Set<string>>() // userId -> Set of active tokens
  private tokenToUser = new Map<string, string>() // token -> userId mapping
  private cleanupInterval: NodeJS.Timeout

  constructor(private readonly jwtService: JwtService) {}

  onModuleInit() {
    // Clean up expired tokens every 5 minutes
    this.cleanupInterval = setInterval(
      () => {
        this.cleanupExpiredTokens()
      },
      5 * 60 * 1000
    )
  }

  /**
   * Blacklist a token with its expiration time
   * @param token - The JWT token to blacklist
   */
  async blacklistToken(token: string): Promise<void> {
    try {
      // Decode token to get expiration and user info
      const decoded = this.jwtService.decode(token) as any
      if (decoded && decoded.exp) {
        const expiresAt = new Date(decoded.exp * 1000)
        const userId = decoded._id

        // Add to blacklist
        this.blacklistedTokens.set(token, expiresAt)

        // Remove from user's active tokens
        if (userId) {
          const userTokens = this.userActiveTokens.get(userId)
          if (userTokens) {
            userTokens.delete(token)
            if (userTokens.size === 0) {
              this.userActiveTokens.delete(userId)
            }
          }
          // Remove from token to user mapping
          this.tokenToUser.delete(token)
        }
      }
    } catch (error) {
      // If we can't decode the token, blacklist it for 1 hour as safety measure
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000)
      this.blacklistedTokens.set(token, expiresAt)
    }
  }

  /**
   * Check if a token is blacklisted
   * @param token - The JWT token to check
   * @returns True if token is blacklisted
   */
  async isTokenBlacklisted(token: string): Promise<boolean> {
    const expiresAt = this.blacklistedTokens.get(token)

    if (!expiresAt) {
      return false
    }

    // If token has expired in blacklist, remove it and return false
    if (new Date() > expiresAt) {
      this.blacklistedTokens.delete(token)
      return false
    }

    return true
  }

  /**
   * Blacklist all tokens for a specific user by their ID
   * @param userId - The user ID
   */
  async blacklistAllUserTokens(userId: string): Promise<void> {
    const userTokens = this.userActiveTokens.get(userId)

    if (!userTokens || userTokens.size === 0) {
      console.log(`No active tokens found for user: ${userId}`)
      return
    }

    const now = new Date()
    let blacklistedCount = 0

    // Blacklist each token for this user
    for (const token of userTokens) {
      try {
        const decoded = this.jwtService.decode(token) as any
        if (decoded && decoded.exp) {
          const expiresAt = new Date(decoded.exp * 1000)

          // Only blacklist if token hasn't expired
          if (expiresAt > now) {
            this.blacklistedTokens.set(token, expiresAt)
            blacklistedCount++
          }
        }
      } catch (error) {
        // If we can't decode, blacklist for 1 hour as safety measure
        const expiresAt = new Date(now.getTime() + 60 * 60 * 1000)
        this.blacklistedTokens.set(token, expiresAt)
        blacklistedCount++
      }

      // Remove from token to user mapping
      this.tokenToUser.delete(token)
    }

    // Clear all tokens for this user
    this.userActiveTokens.delete(userId)

    console.log(`Blacklisted ${blacklistedCount} active tokens for user: ${userId}`)
  }

  /**
   * Clean up expired tokens from memory
   */
  private cleanupExpiredTokens(): void {
    const now = new Date()

    // Clean up blacklisted tokens
    for (const [token, expiresAt] of this.blacklistedTokens.entries()) {
      if (now > expiresAt) {
        this.blacklistedTokens.delete(token)
      }
    }

    // Clean up expired active tokens for users
    for (const [userId, userTokens] of this.userActiveTokens.entries()) {
      const validTokens = new Set<string>()

      for (const token of userTokens) {
        try {
          const decoded = this.jwtService.decode(token) as any
          if (decoded && decoded.exp) {
            const expiresAt = new Date(decoded.exp * 1000)

            // Keep token if it hasn't expired
            if (expiresAt > now) {
              validTokens.add(token)
            } else {
              // Remove expired token from token-to-user mapping
              this.tokenToUser.delete(token)
            }
          }
        } catch (error) {
          // Remove invalid tokens
          this.tokenToUser.delete(token)
        }
      }

      // Update user's active tokens or remove if empty
      if (validTokens.size > 0) {
        this.userActiveTokens.set(userId, validTokens)
      } else {
        this.userActiveTokens.delete(userId)
      }
    }
  }

  /**
   * Get current blacklist size (for monitoring)
   */
  getBlacklistSize(): number {
    return this.blacklistedTokens.size
  }

  /**
   * Track a new token for a user (call this when issuing new tokens)
   * @param token - The JWT token
   * @param userId - The user ID
   */
  async trackToken(token: string, userId: string): Promise<void> {
    // Add token to user's active token set
    if (!this.userActiveTokens.has(userId)) {
      this.userActiveTokens.set(userId, new Set())
    }
    this.userActiveTokens.get(userId)!.add(token)

    // Add token to user mapping
    this.tokenToUser.set(token, userId)
  }

  /**
   * Get active tokens count for a user
   * @param userId - The user ID
   * @returns Number of active tokens
   */
  getUserActiveTokenCount(userId: string): number {
    const userTokens = this.userActiveTokens.get(userId)
    return userTokens ? userTokens.size : 0
  }

  /**
   * Get all active tokens for a user (for debugging/monitoring)
   * @param userId - The user ID
   * @returns Array of token info
   */
  getUserTokens(userId: string): Array<{ token: string; expiresAt?: Date; issuedAt?: Date }> {
    const userTokens = this.userActiveTokens.get(userId)
    if (!userTokens) return []

    return Array.from(userTokens).map((token) => {
      try {
        const decoded = this.jwtService.decode(token) as any
        return {
          token: `${token.substring(0, 10)}...${token.substring(token.length - 10)}`, // Partial token for security
          expiresAt: decoded?.exp ? new Date(decoded.exp * 1000) : undefined,
          issuedAt: decoded?.iat ? new Date(decoded.iat * 1000) : undefined
        }
      } catch {
        return { token: `${token.substring(0, 10)}...${token.substring(token.length - 10)}` }
      }
    })
  }

  /**
   * Clear all blacklisted tokens and active token tracking (for testing/emergency)
   */
  clearBlacklist(): void {
    this.blacklistedTokens.clear()
    this.userActiveTokens.clear()
    this.tokenToUser.clear()
  }
}
