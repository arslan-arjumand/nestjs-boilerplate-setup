import { Injectable, NestMiddleware, HttpException, HttpStatus } from "@nestjs/common"
import { Request, Response, NextFunction } from "express"

interface RateLimitConfig {
  windowMs: number // Time window in milliseconds
  maxRequests: number // Maximum requests per window
  skipSuccessfulRequests?: boolean
  skipFailedRequests?: boolean
  keyGenerator?: (req: Request) => string
}

interface RateLimitEntry {
  count: number
  resetTime: number
  successfulRequests: number
  failedRequests: number
}

@Injectable()
export class RateLimitMiddleware implements NestMiddleware {
  private store = new Map<string, RateLimitEntry>()
  private cleanupInterval: NodeJS.Timeout

  // Default configurations for different endpoint types
  private configs: { [key: string]: RateLimitConfig } = {
    default: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 100
    },
    auth: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 5 // Very strict for auth endpoints
    },
    "auth-signin": {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 5 // 5 attempts per 15 minutes
    },
    "auth-signup": {
      windowMs: 60 * 60 * 1000, // 1 hour
      maxRequests: 3 // 3 signups per hour per IP
    },
    "auth-forgot-password": {
      windowMs: 60 * 60 * 1000, // 1 hour
      maxRequests: 3 // 3 password reset requests per hour
    },
    "auth-refresh": {
      windowMs: 5 * 60 * 1000, // 5 minutes
      maxRequests: 10 // 10 refresh attempts per 5 minutes
    },
    api: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 1000 // Higher limit for regular API calls
    }
  }

  constructor() {
    // Clean up expired entries every 5 minutes
    this.cleanupInterval = setInterval(
      () => {
        this.cleanup()
      },
      5 * 60 * 1000
    )
  }

  use(req: Request, res: Response, next: NextFunction) {
    const config = this.getConfig(req)
    const key = this.generateKey(req, config)
    const now = Date.now()

    let entry = this.store.get(key)

    // Create new entry if doesn't exist or window has passed
    if (!entry || now > entry.resetTime) {
      entry = {
        count: 0,
        resetTime: now + config.windowMs,
        successfulRequests: 0,
        failedRequests: 0
      }
      this.store.set(key, entry)
    }

    // Check if limit exceeded
    if (entry.count >= config.maxRequests) {
      const resetTimeLeft = Math.ceil((entry.resetTime - now) / 1000)

      // Set rate limit headers
      res.set({
        "X-RateLimit-Limit": config.maxRequests.toString(),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": new Date(entry.resetTime).toISOString(),
        "Retry-After": resetTimeLeft.toString()
      })

      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: `Too many requests. Try again in ${resetTimeLeft} seconds.`,
          error: "Too Many Requests"
        },
        HttpStatus.TOO_MANY_REQUESTS
      )
    }

    // Increment counter
    entry.count++

    // Set rate limit headers for successful requests
    res.set({
      "X-RateLimit-Limit": config.maxRequests.toString(),
      "X-RateLimit-Remaining": Math.max(0, config.maxRequests - entry.count).toString(),
      "X-RateLimit-Reset": new Date(entry.resetTime).toISOString()
    })

    // Track success/failure after response
    const originalSend = res.send
    res.send = function (body) {
      if (res.statusCode >= 200 && res.statusCode < 400) {
        entry!.successfulRequests++
      } else {
        entry!.failedRequests++
      }
      return originalSend.call(this, body)
    }

    next()
  }

  /**
   * Get rate limit configuration based on request path
   */
  private getConfig(req: Request): RateLimitConfig {
    const path = req.path.toLowerCase()

    // Auth endpoints get stricter limits
    if (path.includes("/auth/signin")) {
      return this.configs["auth-signin"]
    } else if (path.includes("/auth/signup")) {
      return this.configs["auth-signup"]
    } else if (path.includes("/auth/forgot-password")) {
      return this.configs["auth-forgot-password"]
    } else if (path.includes("/auth/refresh")) {
      return this.configs["auth-refresh"]
    } else if (path.includes("/auth/")) {
      return this.configs["auth"]
    } else if (path.includes("/api/")) {
      return this.configs["api"]
    }

    return this.configs["default"]
  }

  /**
   * Generate unique key for rate limiting (IP + endpoint)
   */
  private generateKey(req: Request, config: RateLimitConfig): string {
    if (config.keyGenerator) {
      return config.keyGenerator(req)
    }

    // Use IP address + endpoint path for default key
    const ip = this.getClientIp(req)
    const endpoint = req.path.toLowerCase()

    return `${ip}:${endpoint}`
  }

  /**
   * Extract client IP address considering proxies
   */
  private getClientIp(req: Request): string {
    return (
      req.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      req.get("x-real-ip") ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      "unknown"
    )
  }

  /**
   * Clean up expired entries from store
   */
  private cleanup(): void {
    const now = Date.now()
    for (const [key, entry] of this.store.entries()) {
      if (now > entry.resetTime) {
        this.store.delete(key)
      }
    }
  }

  /**
   * Get current rate limit stats (for monitoring)
   */
  getStats(): {
    totalEntries: number
    activeIPs: Set<string>
    topEndpoints: Array<{ endpoint: string; requests: number }>
  } {
    const activeIPs = new Set<string>()
    const endpointStats = new Map<string, number>()

    for (const [key, entry] of this.store.entries()) {
      const [ip, endpoint] = key.split(":")
      activeIPs.add(ip)

      const currentCount = endpointStats.get(endpoint) || 0
      endpointStats.set(endpoint, currentCount + entry.count)
    }

    const topEndpoints = Array.from(endpointStats.entries())
      .map(([endpoint, requests]) => ({ endpoint, requests }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 10)

    return {
      totalEntries: this.store.size,
      activeIPs,
      topEndpoints
    }
  }

  /**
   * Clear all rate limit data (for testing/emergency)
   */
  clearAll(): void {
    this.store.clear()
  }

  /**
   * Update configuration for specific endpoint type
   */
  updateConfig(type: string, config: Partial<RateLimitConfig>): void {
    this.configs[type] = { ...this.configs[type], ...config }
  }
}
