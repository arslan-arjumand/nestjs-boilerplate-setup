import { Injectable, Logger } from "@nestjs/common"
import { InjectModel } from "@nestjs/mongoose"
import { Model, Types } from "mongoose"
import { EntityRepository } from "@/modules/common/repository/entity.repository"
import { UserSession, UserSessionDocument, SessionStatus, DeviceType } from "../schema/user-session.schema"
import { Request } from "express"
import * as crypto from "crypto"

export interface CreateSessionDto {
  userId: string
  ipAddress: string
  userAgent: string
  refreshTokenHash?: string
  expiresAt?: Date
  metadata?: any
}

export interface UpdateSessionDto {
  lastAccessedAt?: Date
  requestCount?: number
  refreshTokenHash?: string
  status?: SessionStatus
  terminationReason?: string
  security?: {
    isSuspicious?: boolean
    riskScore?: number
    requiresMFA?: boolean
    isPrivileged?: boolean
  }
}

export interface SessionQueryOptions {
  userId?: string
  status?: SessionStatus
  ipAddress?: string
  deviceType?: DeviceType
  startDate?: Date
  endDate?: Date
  limit?: number
  page?: number
  includeExpired?: boolean
}

@Injectable()
export class UserSessionRepository extends EntityRepository<UserSessionDocument> {
  private readonly logger = new Logger(UserSessionRepository.name)

  constructor(
    @InjectModel(UserSession.name)
    private readonly userSessionModel: Model<UserSessionDocument>
  ) {
    super(userSessionModel)
  }

  /**
   * Create a new user session
   * @param sessionData - Session data
   * @param request - HTTP request for additional context
   * @returns Created session
   */
  async createSession(sessionData: CreateSessionDto, request?: Request): Promise<UserSessionDocument> {
    try {
      const sessionId = this.generateSessionId()
      const deviceInfo = this.parseDeviceInfo(sessionData.userAgent)
      const locationInfo = await this.getLocationFromIP(sessionData.ipAddress)

      const session = new this.userSessionModel({
        userId: new Types.ObjectId(sessionData.userId),
        sessionId,
        status: SessionStatus.ACTIVE,
        ipAddress: sessionData.ipAddress,
        userAgent: sessionData.userAgent,
        device: deviceInfo,
        location: locationInfo,
        refreshTokenHash: sessionData.refreshTokenHash,
        expiresAt: sessionData.expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        security: {
          isSuspicious: false,
          riskScore: 0,
          requiresMFA: false,
          isPrivileged: false
        },
        metadata: sessionData.metadata
      })

      const savedSession = await session.save()

      this.logger.log(`Session created for user ${sessionData.userId}: ${sessionId}`)

      return savedSession
    } catch (error) {
      this.logger.error(`Failed to create session: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Find session by session ID
   * @param sessionId - Session identifier
   * @returns Session if found
   */
  async findBySessionId(sessionId: string): Promise<UserSessionDocument | null> {
    try {
      return await this.userSessionModel
        .findOne({ sessionId, status: SessionStatus.ACTIVE })
        .populate("userId", "email username")
        .exec()
    } catch (error) {
      this.logger.error(`Failed to find session ${sessionId}: ${error.message}`)
      return null
    }
  }

  /**
   * Get all active sessions for a user
   * @param userId - User ID
   * @param options - Query options
   * @returns User's active sessions
   */
  async getUserSessions(
    userId: string,
    options: SessionQueryOptions = {}
  ): Promise<{
    sessions: UserSessionDocument[]
    totalCount: number
  }> {
    try {
      const { status = SessionStatus.ACTIVE, limit = 50, page = 1, includeExpired = false } = options

      const query: any = {
        userId: new Types.ObjectId(userId),
        status
      }

      if (!includeExpired) {
        query.expiresAt = { $gt: new Date() }
      }

      const [sessions, totalCount] = await Promise.all([
        this.userSessionModel
          .find(query)
          .sort({ lastAccessedAt: -1 })
          .limit(limit)
          .skip((page - 1) * limit)
          .exec(),
        this.userSessionModel.countDocuments(query)
      ])

      return { sessions, totalCount }
    } catch (error) {
      this.logger.error(`Failed to get user sessions for ${userId}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Update session activity
   * @param sessionId - Session ID
   * @param updates - Update data
   * @returns Updated session
   */
  async updateSession(sessionId: string, updates: UpdateSessionDto): Promise<UserSessionDocument | null> {
    try {
      const session = await this.userSessionModel.findOneAndUpdate(
        { sessionId, status: SessionStatus.ACTIVE },
        {
          ...updates,
          ...(updates.lastAccessedAt && { lastAccessedAt: updates.lastAccessedAt }),
          ...(updates.requestCount && { $inc: { requestCount: 1 } })
        },
        { new: true }
      )

      if (session) {
        this.logger.debug(`Session updated: ${sessionId}`)
      }

      return session
    } catch (error) {
      this.logger.error(`Failed to update session ${sessionId}: ${error.message}`, error.stack)
      return null
    }
  }

  /**
   * Terminate a session
   * @param sessionId - Session ID
   * @param reason - Termination reason
   * @returns Success status
   */
  async terminateSession(sessionId: string, reason: string = "USER_LOGOUT"): Promise<boolean> {
    try {
      const result = await this.userSessionModel.updateOne(
        { sessionId, status: SessionStatus.ACTIVE },
        {
          status: SessionStatus.TERMINATED,
          terminatedAt: new Date(),
          terminationReason: reason
        }
      )

      if (result.modifiedCount > 0) {
        this.logger.log(`Session terminated: ${sessionId} (${reason})`)
        return true
      }

      return false
    } catch (error) {
      this.logger.error(`Failed to terminate session ${sessionId}: ${error.message}`, error.stack)
      return false
    }
  }

  /**
   * Terminate all sessions for a user
   * @param userId - User ID
   * @param reason - Termination reason
   * @param excludeSessionId - Session to exclude from termination
   * @returns Number of terminated sessions
   */
  async terminateAllUserSessions(
    userId: string,
    reason: string = "LOGOUT_ALL",
    excludeSessionId?: string
  ): Promise<number> {
    try {
      const query: any = {
        userId: new Types.ObjectId(userId),
        status: SessionStatus.ACTIVE
      }

      if (excludeSessionId) {
        query.sessionId = { $ne: excludeSessionId }
      }

      const result = await this.userSessionModel.updateMany(query, {
        status: SessionStatus.TERMINATED,
        terminatedAt: new Date(),
        terminationReason: reason
      })

      this.logger.log(`Terminated ${result.modifiedCount} sessions for user ${userId}`)

      return result.modifiedCount
    } catch (error) {
      this.logger.error(`Failed to terminate all sessions for user ${userId}: ${error.message}`, error.stack)
      return 0
    }
  }

  /**
   * Get session statistics for a user
   * @param userId - User ID
   * @returns Session statistics
   */
  async getUserSessionStats(userId: string) {
    try {
      const [activeCount, totalCount, deviceBreakdown, locationBreakdown] = await Promise.all([
        this.userSessionModel.countDocuments({
          userId: new Types.ObjectId(userId),
          status: SessionStatus.ACTIVE,
          expiresAt: { $gt: new Date() }
        }),

        this.userSessionModel.countDocuments({
          userId: new Types.ObjectId(userId)
        }),

        this.userSessionModel.aggregate([
          { $match: { userId: new Types.ObjectId(userId) } },
          { $group: { _id: "$device.deviceType", count: { $sum: 1 } } }
        ]),

        this.userSessionModel.aggregate([
          { $match: { userId: new Types.ObjectId(userId) } },
          { $group: { _id: "$location.country", count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 5 }
        ])
      ])

      return {
        activeCount,
        totalCount,
        deviceBreakdown: deviceBreakdown.reduce((acc, curr) => {
          acc[curr._id || "Unknown"] = curr.count
          return acc
        }, {}),
        topCountries: locationBreakdown.map((item) => ({
          country: item._id || "Unknown",
          count: item.count
        }))
      }
    } catch (error) {
      this.logger.error(`Failed to get session stats for user ${userId}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Clean up expired sessions
   * @param batchSize - Number of sessions to process at once
   * @returns Number of cleaned up sessions
   */
  async cleanupExpiredSessions(batchSize: number = 1000): Promise<number> {
    try {
      // Mark expired sessions as expired (not delete, for audit trail)
      const result = await this.userSessionModel.updateMany(
        {
          status: SessionStatus.ACTIVE,
          expiresAt: { $lt: new Date() }
        },
        {
          status: SessionStatus.EXPIRED,
          terminatedAt: new Date(),
          terminationReason: "EXPIRED"
        },
        { limit: batchSize }
      )

      if (result.modifiedCount > 0) {
        this.logger.log(`Cleaned up ${result.modifiedCount} expired sessions`)
      }

      return result.modifiedCount
    } catch (error) {
      this.logger.error(`Failed to cleanup expired sessions: ${error.message}`, error.stack)
      return 0
    }
  }

  /**
   * Find suspicious sessions
   * @param riskThreshold - Minimum risk score to consider suspicious
   * @returns Suspicious sessions
   */
  async findSuspiciousSessions(riskThreshold: number = 70): Promise<UserSessionDocument[]> {
    try {
      return await this.userSessionModel
        .find({
          status: SessionStatus.ACTIVE,
          $or: [{ "security.riskScore": { $gte: riskThreshold } }, { "security.isSuspicious": true }]
        })
        .populate("userId", "email username")
        .sort({ "security.riskScore": -1 })
        .limit(100)
        .exec()
    } catch (error) {
      this.logger.error(`Failed to find suspicious sessions: ${error.message}`, error.stack)
      return []
    }
  }

  /**
   * Generate unique session ID
   * @returns Session ID
   */
  private generateSessionId(): string {
    return crypto.randomBytes(32).toString("hex")
  }

  /**
   * Parse device information from user agent
   * @param userAgent - User agent string
   * @returns Device information
   */
  private parseDeviceInfo(userAgent: string): {
    deviceType: DeviceType
    browser?: string
    os?: string
    fingerprint?: string
  } {
    // Simple device detection (in production, use a library like ua-parser-js)
    const ua = userAgent.toLowerCase()

    let deviceType = DeviceType.UNKNOWN
    if (ua.includes("mobile") || ua.includes("iphone") || ua.includes("android")) {
      deviceType = DeviceType.MOBILE
    } else if (ua.includes("tablet") || ua.includes("ipad")) {
      deviceType = DeviceType.TABLET
    } else if (ua.includes("mozilla") || ua.includes("chrome") || ua.includes("safari")) {
      deviceType = DeviceType.DESKTOP
    }

    let browser = "Unknown"
    if (ua.includes("chrome")) browser = "Chrome"
    else if (ua.includes("firefox")) browser = "Firefox"
    else if (ua.includes("safari")) browser = "Safari"
    else if (ua.includes("edge")) browser = "Edge"

    let os = "Unknown"
    if (ua.includes("windows")) os = "Windows"
    else if (ua.includes("macos") || ua.includes("mac os")) os = "macOS"
    else if (ua.includes("linux")) os = "Linux"
    else if (ua.includes("android")) os = "Android"
    else if (ua.includes("ios")) os = "iOS"

    return {
      deviceType,
      browser,
      os,
      fingerprint: Buffer.from(userAgent).toString("base64").substring(0, 16)
    }
  }

  /**
   * Get location information from IP address
   * @param ipAddress - IP address
   * @returns Location information
   */
  private async getLocationFromIP(ipAddress: string): Promise<any> {
    // Placeholder for IP geolocation
    // In production, integrate with services like MaxMind, IPInfo, etc.
    return {
      country: "Unknown",
      region: "Unknown",
      city: "Unknown",
      timezone: "UTC"
    }
  }
}
