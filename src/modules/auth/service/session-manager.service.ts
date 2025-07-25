import { Injectable, Logger } from "@nestjs/common"
import { Request } from "express"
import { UserSessionRepository, CreateSessionDto } from "../repository/user-session.repository"
import { SessionStatus } from "../schema/user-session.schema"
import { SecurityLoggerService, SecurityEventType } from "./security-logger.service"
import * as crypto from "crypto"

@Injectable()
export class SessionManagerService {
  private readonly logger = new Logger(SessionManagerService.name)

  constructor(
    private readonly userSessionRepository: UserSessionRepository,
    private readonly securityLogger: SecurityLoggerService
  ) {}

  /**
   * Create a new session when user logs in
   * @param userId - User ID
   * @param request - HTTP request
   * @param refreshTokenHash - Hashed refresh token
   * @param metadata - Additional session metadata
   * @returns Created session
   */
  async createSession(userId: string, request: Request, refreshTokenHash?: string, metadata?: any) {
    try {
      const sessionData: CreateSessionDto = {
        userId,
        ipAddress: this.extractIpAddress(request),
        userAgent: request.get("User-Agent") || "Unknown",
        refreshTokenHash,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        metadata: {
          ...metadata,
          loginTimestamp: new Date(),
          deviceFingerprint: this.generateDeviceFingerprint(request)
        }
      }

      const session = await this.userSessionRepository.createSession(sessionData, request)

      // Log session creation
      await this.securityLogger.logSecurityEvent(SecurityEventType.SESSION_CREATED, request, userId, undefined, true, {
        sessionId: session.sessionId,
        deviceType: session.device.deviceType,
        location: session.location
      })

      // Attach session ID to request for future reference
      ;(request as any).sessionId = session.sessionId

      this.logger.log(`Session created for user ${userId}: ${session.sessionId}`)

      return session
    } catch (error) {
      this.logger.error(`Failed to create session for user ${userId}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Update session activity
   * @param sessionId - Session ID
   * @param request - Current request
   */
  async updateSessionActivity(sessionId: string, request?: Request) {
    try {
      if (!sessionId) return

      const updates = {
        lastAccessedAt: new Date(),
        requestCount: 1 // This will be incremented in repository
      }

      // Calculate risk score if request provided
      if (request) {
        const riskAssessment = this.securityLogger.assessRisk(request)
        if (riskAssessment.riskScore > 30) {
          updates["security"] = {
            riskScore: riskAssessment.riskScore,
            isSuspicious: riskAssessment.riskScore > 70
          }
        }
      }

      await this.userSessionRepository.updateSession(sessionId, updates)
    } catch (error) {
      this.logger.warn(`Failed to update session activity for ${sessionId}: ${error.message}`)
      // Don't throw - session activity update shouldn't break the request
    }
  }

  /**
   * Terminate a session
   * @param sessionId - Session ID
   * @param reason - Termination reason
   * @param request - HTTP request for logging
   */
  async terminateSession(sessionId: string, reason: string = "USER_LOGOUT", request?: Request) {
    try {
      const success = await this.userSessionRepository.terminateSession(sessionId, reason)

      if (success && request) {
        // Extract user ID from session for logging
        const session = await this.userSessionRepository.findBySessionId(sessionId)
        if (session) {
          await this.securityLogger.logSecurityEvent(
            SecurityEventType.SESSION_TERMINATED,
            request,
            session.userId.toString(),
            undefined,
            true,
            {
              sessionId,
              reason,
              deviceType: session.device.deviceType
            }
          )
        }
      }

      return success
    } catch (error) {
      this.logger.error(`Failed to terminate session ${sessionId}: ${error.message}`, error.stack)
      return false
    }
  }

  /**
   * Terminate all sessions for a user
   * @param userId - User ID
   * @param reason - Termination reason
   * @param excludeSessionId - Session to keep active
   * @param request - HTTP request for logging
   * @returns Number of terminated sessions
   */
  async terminateAllUserSessions(
    userId: string,
    reason: string = "LOGOUT_ALL",
    excludeSessionId?: string,
    request?: Request
  ) {
    try {
      const terminatedCount = await this.userSessionRepository.terminateAllUserSessions(
        userId,
        reason,
        excludeSessionId
      )

      if (terminatedCount > 0 && request) {
        await this.securityLogger.logSecurityEvent(SecurityEventType.LOGOUT_ALL, request, userId, undefined, true, {
          terminatedSessions: terminatedCount,
          reason,
          excludedSession: excludeSessionId
        })
      }

      return terminatedCount
    } catch (error) {
      this.logger.error(`Failed to terminate all sessions for user ${userId}: ${error.message}`, error.stack)
      return 0
    }
  }

  /**
   * Get user's active sessions
   * @param userId - User ID
   * @param includeDetails - Whether to include detailed session info
   * @returns User sessions
   */
  async getUserSessions(userId: string, includeDetails: boolean = false) {
    try {
      const result = await this.userSessionRepository.getUserSessions(userId, {
        status: SessionStatus.ACTIVE,
        includeExpired: false,
        limit: 50
      })

      if (!includeDetails) {
        // Return simplified session info for API responses
        return {
          activeCount: result.totalCount,
          sessions: result.sessions.map((session) => ({
            sessionId: session.sessionId.substring(0, 8) + "...", // Truncated for security
            device: session.device,
            location: session.location,
            createdAt: session.createdAt,
            lastAccessedAt: session.lastAccessedAt,
            security: {
              riskScore: session.security.riskScore,
              isSuspicious: session.security.isSuspicious
            }
          }))
        }
      }

      return result
    } catch (error) {
      this.logger.error(`Failed to get sessions for user ${userId}: ${error.message}`, error.stack)
      return { sessions: [], totalCount: 0 }
    }
  }

  /**
   * Get session statistics for a user
   * @param userId - User ID
   * @returns Session statistics
   */
  async getUserSessionStats(userId: string) {
    try {
      return await this.userSessionRepository.getUserSessionStats(userId)
    } catch (error) {
      this.logger.error(`Failed to get session stats for user ${userId}: ${error.message}`, error.stack)
      return {
        activeCount: 0,
        totalCount: 0,
        deviceBreakdown: {},
        topCountries: []
      }
    }
  }

  /**
   * Find and handle suspicious sessions
   * @param riskThreshold - Minimum risk score to consider suspicious
   * @returns Number of sessions flagged/handled
   */
  async handleSuspiciousSessions(riskThreshold: number = 80) {
    try {
      const suspiciousSessions = await this.userSessionRepository.findSuspiciousSessions(riskThreshold)
      let handledCount = 0

      for (const session of suspiciousSessions) {
        // Flag session as suspicious
        await this.userSessionRepository.updateSession(session.sessionId, {
          security: {
            ...session.security,
            isSuspicious: true,
            requiresMFA: true // Could require additional verification
          }
        })

        // Log suspicious activity
        const mockRequest = this.createMockRequest(session.ipAddress, session.userAgent)
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.SUSPICIOUS_ACTIVITY,
          mockRequest as Request,
          session.userId.toString(),
          undefined,
          false,
          {
            sessionId: session.sessionId,
            riskScore: session.security.riskScore,
            automaticallyFlagged: true
          }
        )

        handledCount++
      }

      if (handledCount > 0) {
        this.logger.warn(`Flagged ${handledCount} suspicious sessions`)
      }

      return handledCount
    } catch (error) {
      this.logger.error(`Failed to handle suspicious sessions: ${error.message}`, error.stack)
      return 0
    }
  }

  /**
   * Clean up expired sessions
   * @param batchSize - Number of sessions to process at once
   * @returns Number of cleaned up sessions
   */
  async cleanupExpiredSessions(batchSize: number = 1000) {
    try {
      return await this.userSessionRepository.cleanupExpiredSessions(batchSize)
    } catch (error) {
      this.logger.error(`Failed to cleanup expired sessions: ${error.message}`, error.stack)
      return 0
    }
  }

  /**
   * Get session by ID (for internal use)
   * @param sessionId - Session ID
   * @returns Session if found
   */
  async getSessionById(sessionId: string) {
    try {
      return await this.userSessionRepository.findBySessionId(sessionId)
    } catch (error) {
      this.logger.error(`Failed to get session ${sessionId}: ${error.message}`)
      return null
    }
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
   * Generate device fingerprint
   * @param request - HTTP request
   * @returns Device fingerprint
   */
  private generateDeviceFingerprint(request: Request): string {
    const userAgent = request.get("User-Agent") || ""
    const acceptLanguage = request.get("Accept-Language") || ""
    const acceptEncoding = request.get("Accept-Encoding") || ""

    return crypto
      .createHash("sha256")
      .update(`${userAgent}${acceptLanguage}${acceptEncoding}`)
      .digest("hex")
      .substring(0, 16)
  }

  /**
   * Create a mock request object for logging purposes
   * @param ipAddress - IP address
   * @param userAgent - User agent
   * @returns Mock request object
   */
  private createMockRequest(ipAddress: string, userAgent: string): Request {
    return {
      headers: {
        "user-agent": userAgent,
        "x-forwarded-for": ipAddress
      },
      get: (header: string) => {
        const headers: any = {
          "user-agent": userAgent,
          "x-forwarded-for": ipAddress
        }
        return headers[header.toLowerCase()]
      },
      connection: { remoteAddress: ipAddress },
      socket: { remoteAddress: ipAddress },
      cookies: {}
    } as any
  }
}
