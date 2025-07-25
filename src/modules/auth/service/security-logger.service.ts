import { Injectable } from "@nestjs/common"
import { Request } from "express"
import { SecurityEventRepository } from "../repository/security-event.repository"

export enum SecurityEventType {
  LOGIN_SUCCESS = "LOGIN_SUCCESS",
  LOGIN_FAILED = "LOGIN_FAILED",
  LOGIN_BLOCKED = "LOGIN_BLOCKED",
  TOKEN_REFRESH = "TOKEN_REFRESH",
  TOKEN_REFRESH_FAILED = "TOKEN_REFRESH_FAILED",
  LOGOUT = "LOGOUT",
  LOGOUT_ALL = "LOGOUT_ALL",
  PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED",
  PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED",
  SIGNUP_SUCCESS = "SIGNUP_SUCCESS",
  SIGNUP_FAILED = "SIGNUP_FAILED",
  ACCOUNT_LOCKED = "ACCOUNT_LOCKED",
  SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY",
  TOKEN_BLACKLISTED = "TOKEN_BLACKLISTED",
  SESSION_CREATED = "SESSION_CREATED",
  SESSION_TERMINATED = "SESSION_TERMINATED"
}

export interface SecurityEvent {
  eventType: SecurityEventType
  userId?: string
  email?: string
  ipAddress: string
  userAgent: string
  timestamp: Date
  success: boolean
  metadata?: any
  riskScore?: number
}

@Injectable()
export class SecurityLoggerService {
  private securityEvents: SecurityEvent[] = [] // Keep in-memory for fallback
  private readonly MAX_EVENTS_IN_MEMORY = 1000

  constructor(private readonly securityEventRepository: SecurityEventRepository) {}

  /**
   * Log a security event (now persistent in MongoDB)
   * @param eventType - Type of security event
   * @param request - HTTP request object
   * @param userId - User ID if available
   * @param email - User email if available
   * @param success - Whether the event was successful
   * @param metadata - Additional event metadata
   */
  async logSecurityEvent(
    eventType: SecurityEventType,
    request: Request,
    userId?: string,
    email?: string,
    success: boolean = true,
    metadata?: any
  ): Promise<void> {
    const riskScore = this.calculateRiskScore(eventType, request, success, metadata)

    // Create event object for in-memory fallback
    const event: SecurityEvent = {
      eventType,
      userId,
      email,
      ipAddress: this.extractIpAddress(request),
      userAgent: request.get("User-Agent") || "Unknown",
      timestamp: new Date(),
      success,
      metadata,
      riskScore
    }

    try {
      // Log to MongoDB (primary storage)
      await this.securityEventRepository.createFromRequest(
        eventType,
        request,
        userId,
        email,
        success,
        metadata,
        riskScore
      )
    } catch (error) {
      console.error("❌ Failed to log security event to MongoDB:", error.message)

      // Fallback to in-memory storage
      this.securityEvents.push(event)
      if (this.securityEvents.length > this.MAX_EVENTS_IN_MEMORY) {
        this.securityEvents.shift()
      }
    }

    // Always log to console for real-time monitoring
    this.logToConsole(event)
  }

  /**
   * Get recent security events from MongoDB
   * @param limit - Number of events to retrieve
   * @param eventType - Filter by event type
   * @param userId - Filter by user ID
   * @returns Recent security events
   */
  async getRecentEvents(limit: number = 50, eventType?: SecurityEventType, userId?: string) {
    try {
      const result = await this.securityEventRepository.findEvents({
        eventType,
        userId,
        limit,
        sortBy: "createdAt",
        sortOrder: "desc"
      })

      return result.events
    } catch (error) {
      console.error("❌ Failed to get recent events from MongoDB:", error.message)

      // Fallback to in-memory events
      let events = [...this.securityEvents].reverse()

      if (eventType) {
        events = events.filter((event) => event.eventType === eventType)
      }
      if (userId) {
        events = events.filter((event) => event.userId === userId)
      }

      return events.slice(0, limit)
    }
  }

  /**
   * Get failed login attempts from MongoDB
   * @param identifier - Email, user ID, or IP address
   * @param timeWindow - Time window in milliseconds
   * @returns Number of failed attempts
   */
  async getFailedAttempts(identifier: string, timeWindow: number = 15 * 60 * 1000): Promise<number> {
    try {
      return await this.securityEventRepository.getFailedAttempts(identifier, timeWindow)
    } catch (error) {
      console.error("❌ Failed to get failed attempts from MongoDB:", error.message)

      // Fallback to in-memory calculation
      const cutoffTime = new Date(Date.now() - timeWindow)
      return this.securityEvents.filter(
        (event) =>
          (event.email === identifier || event.userId === identifier || event.ipAddress === identifier) &&
          (event.eventType === SecurityEventType.LOGIN_FAILED || event.eventType === SecurityEventType.LOGIN_BLOCKED) &&
          !event.success &&
          event.timestamp >= cutoffTime
      ).length
    }
  }

  /**
   * Get security statistics
   * @param days - Number of days to analyze
   * @returns Security statistics
   */
  async getSecurityStats(days: number = 30) {
    try {
      return await this.securityEventRepository.getSecurityStats(days)
    } catch (error) {
      console.error("❌ Failed to get security stats from MongoDB:", error.message)

      // Fallback to basic in-memory stats
      const cutoffTime = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
      const recentEvents = this.securityEvents.filter((event) => event.timestamp >= cutoffTime)

      return {
        totalEvents: recentEvents.length,
        successfulEvents: recentEvents.filter((e) => e.success).length,
        failedEvents: recentEvents.filter((e) => !e.success).length,
        averageRiskScore: recentEvents.reduce((sum, e) => sum + (e.riskScore || 0), 0) / recentEvents.length || 0,
        eventsByType: recentEvents.reduce((acc, e) => {
          acc[e.eventType] = (acc[e.eventType] || 0) + 1
          return acc
        }, {} as any),
        topRiskyIPs: [],
        suspiciousActivity: []
      }
    }
  }

  /**
   * Assess risk for a request
   * @param request - HTTP request
   * @returns Risk assessment
   */
  assessRisk(request: Request): { riskScore: number; reasons: string[] } {
    let riskScore = 0
    const reasons: string[] = []

    const ip = this.extractIpAddress(request)
    const userAgent = request.get("User-Agent") || ""

    // Check for suspicious IP patterns
    if (ip === "unknown" || ip.startsWith("10.") || ip.startsWith("192.168.")) {
      // Local/unknown IPs have lower base risk
      riskScore += 5
    }

    // Check user agent
    if (!userAgent || userAgent.length < 10) {
      riskScore += 20
      reasons.push("Suspicious or missing user agent")
    }

    // Check for common bot patterns
    if (userAgent.toLowerCase().includes("bot") || userAgent.toLowerCase().includes("crawler")) {
      riskScore += 30
      reasons.push("Bot-like user agent detected")
    }

    // Check recent failed attempts from this IP
    const recentFailures = this.securityEvents.filter(
      (event) => event.ipAddress === ip && !event.success && event.timestamp > new Date(Date.now() - 15 * 60 * 1000) // Last 15 minutes
    ).length

    if (recentFailures > 3) {
      riskScore += 40
      reasons.push(`${recentFailures} recent failed attempts from this IP`)
    }

    // Check for unusual headers or patterns
    const forwarded = request.get("X-Forwarded-For")
    if (forwarded && forwarded.split(",").length > 3) {
      riskScore += 15
      reasons.push("Multiple proxy headers detected")
    }

    return { riskScore: Math.min(riskScore, 100), reasons }
  }

  /**
   * Extract IP address from request
   * @param request - HTTP request
   * @returns IP address
   */
  private extractIpAddress(request: Request): string {
    return (
      (request.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
      (request.headers["x-real-ip"] as string) ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      "unknown"
    )
  }

  /**
   * Calculate risk score for an event
   * @param eventType - Type of security event
   * @param request - HTTP request
   * @param success - Whether event was successful
   * @param metadata - Additional metadata
   * @returns Risk score (0-100)
   */
  private calculateRiskScore(eventType: SecurityEventType, request: Request, success: boolean, metadata?: any): number {
    let baseScore = 0

    // Base scores by event type
    const eventRiskScores: { [key in SecurityEventType]: number } = {
      [SecurityEventType.LOGIN_SUCCESS]: 0,
      [SecurityEventType.LOGIN_FAILED]: 30,
      [SecurityEventType.LOGIN_BLOCKED]: 60,
      [SecurityEventType.TOKEN_REFRESH]: 5,
      [SecurityEventType.TOKEN_REFRESH_FAILED]: 40,
      [SecurityEventType.LOGOUT]: 0,
      [SecurityEventType.LOGOUT_ALL]: 10,
      [SecurityEventType.PASSWORD_RESET_REQUESTED]: 20,
      [SecurityEventType.PASSWORD_RESET_COMPLETED]: 10,
      [SecurityEventType.SIGNUP_SUCCESS]: 5,
      [SecurityEventType.SIGNUP_FAILED]: 25,
      [SecurityEventType.ACCOUNT_LOCKED]: 80,
      [SecurityEventType.SUSPICIOUS_ACTIVITY]: 90,
      [SecurityEventType.TOKEN_BLACKLISTED]: 50,
      [SecurityEventType.SESSION_CREATED]: 0,
      [SecurityEventType.SESSION_TERMINATED]: 5
    }

    baseScore = eventRiskScores[eventType] || 0

    // Increase score for failed events
    if (!success) {
      baseScore += 20
    }

    // Additional risk factors from request assessment
    const riskAssessment = this.assessRisk(request)
    baseScore += Math.floor(riskAssessment.riskScore * 0.3) // 30% of request risk

    // Metadata-based adjustments
    if (metadata?.lockTimeRemaining) {
      baseScore += 20
    }
    if (metadata?.reason === "User already exists") {
      baseScore -= 10 // Less risky than other failures
    }

    return Math.min(Math.max(baseScore, 0), 100)
  }

  /**
   * Log event to console with color coding
   * @param event - Security event
   */
  private logToConsole(event: SecurityEvent): void {
    const timestamp = event.timestamp.toISOString()
    const riskIndicator = this.getRiskIndicator(event.riskScore || 0)
    const statusIcon = event.success ? "✅" : "❌"

    const logMessage = `[SECURITY EVENT] ${statusIcon} ${timestamp} | ${event.eventType} | IP: ${event.ipAddress} | User: ${event.userId || event.email || "Anonymous"} | Success: ${event.success} | Risk: ${event.riskScore || 0}/100 ${riskIndicator}`

    // Color-coded console output
    if (event.success) {
      if ((event.riskScore || 0) > 50) {
        console.log("\x1b[33m%s\x1b[0m", logMessage) // Yellow for successful but risky
      } else {
        console.log("\x1b[32m%s\x1b[0m", logMessage) // Green for successful and safe
      }
    } else {
      if ((event.riskScore || 0) > 70) {
        console.log("\x1b[41m%s\x1b[0m", logMessage) // Red background for critical failures
      } else {
        console.log("\x1b[31m%s\x1b[0m", logMessage) // Red for failures
      }
    }

    // Log metadata if present
    if (event.metadata && Object.keys(event.metadata).length > 0) {
      console.log("\x1b[36m%s\x1b[0m", `  └─ Metadata: ${JSON.stringify(event.metadata)}`)
    }
  }

  /**
   * Get risk indicator emoji
   * @param riskScore - Risk score
   * @returns Risk indicator
   */
  private getRiskIndicator(riskScore: number): string {
    if (riskScore >= 80) return "🔴"
    if (riskScore >= 60) return "🟠"
    if (riskScore >= 40) return "🟡"
    if (riskScore >= 20) return "🟢"
    return "⚪"
  }
}
