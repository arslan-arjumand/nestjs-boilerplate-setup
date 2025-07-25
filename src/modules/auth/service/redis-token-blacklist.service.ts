import { Injectable } from "@nestjs/common"
import { JwtService } from "@nestjs/jwt"
import { RedisService } from "@/modules/redis/redis.service"

@Injectable()
export class RedisTokenBlacklistService {
  private readonly BLACKLIST_PREFIX = "blacklist:"
  private readonly USER_TOKENS_PREFIX = "user_tokens:"
  private readonly TOKEN_USER_PREFIX = "token_user:"
  private readonly USER_SESSION_COUNT_PREFIX = "session_count:"

  constructor(
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService
  ) {}

  /**
   * Get full tokens for a user (not truncated)
   * @param userId - The user ID
   * @returns Array of full tokens
   */
  async getUserFullTokens(userId: string): Promise<string[]> {
    try {
      return await this.redisService.smembers(`${this.USER_TOKENS_PREFIX}${userId}`)
    } catch (error) {
      console.error("❌ Error getting user full tokens:", error)
      return []
    }
  }

  /**
   * Blacklist a token with improved atomic operations and error handling
   * @param token - The JWT token to blacklist
   */
  async blacklistToken(token: string): Promise<void> {
    try {
      const decoded = this.jwtService.decode(token) as any
      const userId = decoded?._id

      if (decoded && decoded.exp) {
        const expiresAt = decoded.exp
        const ttl = expiresAt - Math.floor(Date.now() / 1000)

        if (ttl > 0) {
          // Use Redis transaction for atomic operations
          const pipeline = this.redisService.pipeline()

          // Add token to blacklist with TTL
          pipeline.setex(`${this.BLACKLIST_PREFIX}${token}`, ttl, "1")

          // Remove token from user's active tokens
          if (userId) {
            pipeline.srem(`${this.USER_TOKENS_PREFIX}${userId}`, token)
            pipeline.del(`${this.TOKEN_USER_PREFIX}${token}`)
          }

          // Execute all operations atomically
          const results = await pipeline.exec()

          // Check if any operation failed
          const hasFailures = results?.some(([error]) => error !== null)
          if (hasFailures) {
            console.error("Some blacklist operations failed:", results)
          }

          // Update session count after successful blacklist operations
          if (userId && !hasFailures) {
            try {
              const remainingTokens = await this.redisService.scard(`${this.USER_TOKENS_PREFIX}${userId}`)
              if (remainingTokens === 0) {
                await this.redisService.del(`${this.USER_SESSION_COUNT_PREFIX}${userId}`)
                await this.redisService.del(`${this.USER_TOKENS_PREFIX}${userId}`)
              } else {
                await this.redisService.set(`${this.USER_SESSION_COUNT_PREFIX}${userId}`, remainingTokens.toString())
              }
            } catch (error) {
              console.warn("Failed to update session count:", error)
            }
          }

          console.log(`🚫 Token blacklisted for user ${userId}`)
        } else {
          console.warn("Attempted to blacklist expired token:", { userId, ttl })
        }
      }
    } catch (error) {
      console.error("❌ Error blacklisting token:", error)

      // Fallback: blacklist for 1 hour if we can't decode
      try {
        const ttl = 60 * 60 // 1 hour
        await this.redisService.setex(`${this.BLACKLIST_PREFIX}${token}`, ttl, "1")
        console.log("Token blacklisted with fallback TTL")
      } catch (fallbackError) {
        console.error("Critical: Failed to blacklist token even with fallback:", fallbackError)
        throw new Error("Failed to blacklist token")
      }
    }
  }

  /**
   * Check if a token is blacklisted
   * @param token - The JWT token to check
   * @returns True if token is blacklisted
   */
  async isTokenBlacklisted(token: string): Promise<boolean> {
    try {
      const result = await this.redisService.get(`${this.BLACKLIST_PREFIX}${token}`)
      return result === "1"
    } catch (error) {
      console.error("❌ Error checking token blacklist:", error)
      // Fail secure: if we can't check, assume it's not blacklisted
      return false
    }
  }

  /**
   * Track a new token for a user with improved error handling
   * @param token - The JWT token
   * @param userId - The user ID
   */
  async trackToken(token: string, userId: string): Promise<void> {
    try {
      const decoded = this.jwtService.decode(token) as any
      const ttl = decoded?.exp ? decoded.exp - Math.floor(Date.now() / 1000) : 60 * 60

      if (ttl <= 0) {
        console.warn("Attempted to track expired token:", { userId, ttl })
        return
      }

      // Use atomic operations
      const pipeline = this.redisService.pipeline()

      // Add token to user's active token set
      pipeline.sadd(`${this.USER_TOKENS_PREFIX}${userId}`, token)
      pipeline.expire(`${this.USER_TOKENS_PREFIX}${userId}`, ttl)

      // Create token-to-user mapping
      pipeline.setex(`${this.TOKEN_USER_PREFIX}${token}`, ttl, userId)

      // Get token count
      pipeline.scard(`${this.USER_TOKENS_PREFIX}${userId}`)

      const results = await pipeline.exec()

      // Check for failures
      const hasFailures = results?.some(([error]) => error !== null)
      if (hasFailures) {
        console.error("Some token tracking operations failed:", results)
        throw new Error("Failed to track token properly")
      }

      // Update session count
      const tokenCount = results?.[results.length - 1]?.[1] as number
      if (tokenCount !== undefined) {
        try {
          await this.redisService.setex(`${this.USER_SESSION_COUNT_PREFIX}${userId}`, ttl, tokenCount.toString())
        } catch (error) {
          console.warn("Failed to update session count:", error)
        }
      }

      console.log(`✅ Token tracked for user ${userId} (${tokenCount} total)`)
    } catch (error) {
      console.error("❌ Error tracking token:", error)
      throw error
    }
  }

  /**
   * Enhanced method to blacklist all tokens for a user with better error handling
   * @param userId - The user ID
   */
  async blacklistAllUserTokens(userId: string): Promise<void> {
    try {
      // Get all tokens for the user
      const userTokens = await this.redisService.smembers(`${this.USER_TOKENS_PREFIX}${userId}`)

      if (!userTokens || userTokens.length === 0) {
        console.log(`ℹ️ No active tokens found for user: ${userId}`)
        return
      }

      console.log(`🔄 Blacklisting ${userTokens.length} tokens for user: ${userId}`)

      // Use batch operations for efficiency
      const pipeline = this.redisService.pipeline()
      let blacklistedCount = 0

      for (const token of userTokens) {
        try {
          const decoded = this.jwtService.decode(token) as any

          if (decoded && decoded.exp) {
            const ttl = decoded.exp - Math.floor(Date.now() / 1000)

            if (ttl > 0) {
              pipeline.setex(`${this.BLACKLIST_PREFIX}${token}`, ttl, "1")
              blacklistedCount++
            } else {
              console.warn("Skipping expired token:", { userId, token: token.substring(0, 10) })
            }
          } else {
            // Fallback TTL for problematic tokens
            pipeline.setex(`${this.BLACKLIST_PREFIX}${token}`, 60 * 60, "1")
            blacklistedCount++
          }

          // Clean up token-user mapping
          pipeline.del(`${this.TOKEN_USER_PREFIX}${token}`)
        } catch (error) {
          console.error(`❌ Error processing token for user ${userId}:`, error)
          // Still blacklist with fallback TTL
          pipeline.setex(`${this.BLACKLIST_PREFIX}${token}`, 60 * 60, "1")
          pipeline.del(`${this.TOKEN_USER_PREFIX}${token}`)
          blacklistedCount++
        }
      }

      // Clean up user's token tracking
      pipeline.del(`${this.USER_TOKENS_PREFIX}${userId}`)
      pipeline.del(`${this.USER_SESSION_COUNT_PREFIX}${userId}`)

      // Execute all operations
      const results = await pipeline.exec()

      // Check for failures
      const hasFailures = results?.some(([error]) => error !== null)
      if (hasFailures) {
        console.error("Some blacklist operations failed for user:", userId, results)
      }

      console.log(`🚫 Successfully blacklisted ${blacklistedCount} tokens for user: ${userId}`)
    } catch (error) {
      console.error("❌ Critical error blacklisting all user tokens:", error)
      throw error
    }
  }

  /**
   * Get active tokens count for a user
   * @param userId - The user ID
   * @returns Number of active tokens
   */
  async getUserActiveTokenCount(userId: string): Promise<number> {
    try {
      const count = await this.redisService.get(`${this.USER_SESSION_COUNT_PREFIX}${userId}`)
      return count ? parseInt(count) : 0
    } catch (error) {
      console.error("❌ Error getting user token count:", error)
      return 0
    }
  }

  /**
   * Get all active tokens for a user (for debugging/monitoring)
   * @param userId - The user ID
   * @returns Array of token info
   */
  async getUserTokens(
    userId: string
  ): Promise<Array<{ token: string; expiresAt?: Date; issuedAt?: Date; deviceInfo?: string }>> {
    try {
      const userTokens = await this.redisService.smembers(`${this.USER_TOKENS_PREFIX}${userId}`)

      if (!userTokens || userTokens.length === 0) {
        return []
      }

      return userTokens.map((token) => {
        try {
          const decoded = this.jwtService.decode(token) as any
          return {
            token: `${token.substring(0, 10)}...${token.substring(token.length - 10)}`, // Partial for security
            expiresAt: decoded?.exp ? new Date(decoded.exp * 1000) : undefined,
            issuedAt: decoded?.iat ? new Date(decoded.iat * 1000) : undefined,
            deviceInfo: decoded?.device || undefined
          }
        } catch {
          return {
            token: `${token.substring(0, 10)}...${token.substring(token.length - 10)}`,
            expiresAt: undefined,
            issuedAt: undefined
          }
        }
      })
    } catch (error) {
      console.error("❌ Error getting user tokens:", error)
      return []
    }
  }

  /**
   * Get blacklist statistics for monitoring
   */
  async getBlacklistStats(): Promise<{
    blacklistedTokensCount: number
    activeUsersWithTokens: number
    totalActiveSessions: number
  }> {
    try {
      const pipeline = this.redisService.pipeline()

      // Count blacklisted tokens (approximate)
      pipeline.eval(
        `
        local keys = redis.call('KEYS', '${this.BLACKLIST_PREFIX}*')
        return #keys
      `,
        0
      )

      // Count users with active tokens
      pipeline.eval(
        `
        local keys = redis.call('KEYS', '${this.USER_TOKENS_PREFIX}*')
        return #keys
      `,
        0
      )

      // Count total active sessions (sum of all user session counts)
      pipeline.eval(
        `
        local keys = redis.call('KEYS', '${this.USER_SESSION_COUNT_PREFIX}*')
        local total = 0
        for i = 1, #keys do
          local count = redis.call('GET', keys[i])
          if count then
            total = total + tonumber(count)
          end
        end
        return total
      `,
        0
      )

      const results = await pipeline.exec()

      return {
        blacklistedTokensCount: (results?.[0]?.[1] as number) || 0,
        activeUsersWithTokens: (results?.[1]?.[1] as number) || 0,
        totalActiveSessions: (results?.[2]?.[1] as number) || 0
      }
    } catch (error) {
      console.error("❌ Error getting blacklist stats:", error)
      return {
        blacklistedTokensCount: 0,
        activeUsersWithTokens: 0,
        totalActiveSessions: 0
      }
    }
  }

  /**
   * Clear all blacklisted tokens and session data (for testing/emergency)
   */
  async clearAll(): Promise<void> {
    try {
      const pipeline = this.redisService.pipeline()

      // Clear all blacklist entries
      const blacklistKeys = await this.redisService.keys(`${this.BLACKLIST_PREFIX}*`)
      const userTokenKeys = await this.redisService.keys(`${this.USER_TOKENS_PREFIX}*`)
      const tokenUserKeys = await this.redisService.keys(`${this.TOKEN_USER_PREFIX}*`)
      const sessionCountKeys = await this.redisService.keys(`${this.USER_SESSION_COUNT_PREFIX}*`)

      const allKeys = [...blacklistKeys, ...userTokenKeys, ...tokenUserKeys, ...sessionCountKeys]

      if (allKeys.length > 0) {
        pipeline.del(...allKeys)
        await pipeline.exec()
      }

      console.log(`🧹 Cleared ${allKeys.length} Redis keys for token blacklist service`)
    } catch (error) {
      console.error("❌ Error clearing all data:", error)
    }
  }
}
