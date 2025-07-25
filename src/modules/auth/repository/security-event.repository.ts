import { Injectable, Logger } from "@nestjs/common"
import { InjectModel } from "@nestjs/mongoose"
import { Model, Types } from "mongoose"
import { EntityRepository } from "@/modules/common/repository/entity.repository"
import { SecurityEvent, SecurityEventDocument, SecurityEventType } from "../schema/security-event.schema"
import { Request } from "express"

export interface SecurityEventCreateDto {
  eventType: SecurityEventType
  userId?: string
  email?: string
  ipAddress: string
  userAgent: string
  success: boolean
  riskScore?: number
  sessionId?: string
  deviceFingerprint?: string
  location?: {
    country: string
    region: string
    city: string
    timezone: string
  }
  metadata?: any
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
}

export interface SecurityEventQueryOptions {
  userId?: string
  eventType?: SecurityEventType
  success?: boolean
  ipAddress?: string
  severity?: string
  startDate?: Date
  endDate?: Date
  limit?: number
  page?: number
  sortBy?: string
  sortOrder?: "asc" | "desc"
}

export interface SecurityEventStats {
  totalEvents: number
  successfulEvents: number
  failedEvents: number
  averageRiskScore: number
  eventsByType: { [key: string]: number }
  topRiskyIPs: Array<{ ip: string; count: number; avgRiskScore: number }>
  suspiciousActivity: Array<{
    userId?: string
    email?: string
    ipAddress: string
    eventCount: number
    riskScore: number
  }>
}

@Injectable()
export class SecurityEventRepository extends EntityRepository<SecurityEventDocument> {
  private readonly logger = new Logger(SecurityEventRepository.name)

  constructor(
    @InjectModel(SecurityEvent.name)
    private readonly securityEventModel: Model<SecurityEventDocument>
  ) {
    super(securityEventModel)
  }

  /**
   * Create a new security event with specific data
   * @param eventData - Security event data
   * @returns Created security event
   */
  async createSecurityEvent(eventData: SecurityEventCreateDto): Promise<SecurityEventDocument> {
    try {
      const securityEvent = new this.securityEventModel({
        ...eventData,
        userId: eventData.userId ? new Types.ObjectId(eventData.userId) : undefined,
        severity:
          eventData.severity || this.calculateSeverity(eventData.eventType, eventData.success, eventData.riskScore)
      })

      const savedEvent = await securityEvent.save()

      this.logger.debug(`Security event created: ${eventData.eventType} - ${eventData.success ? "SUCCESS" : "FAILED"}`)

      return savedEvent
    } catch (error) {
      this.logger.error(`Failed to create security event: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Create security event from HTTP request
   * @param eventType - Type of security event
   * @param request - HTTP request object
   * @param userId - User ID if available
   * @param email - User email if available
   * @param success - Whether the event was successful
   * @param metadata - Additional event metadata
   * @param riskScore - Risk score for the event
   * @returns Created security event
   */
  async createFromRequest(
    eventType: SecurityEventType,
    request: Request,
    userId?: string,
    email?: string,
    success: boolean = true,
    metadata?: any,
    riskScore?: number
  ): Promise<SecurityEventDocument> {
    const eventData: SecurityEventCreateDto = {
      eventType,
      userId,
      email,
      ipAddress: this.extractIpAddress(request),
      userAgent: request.get("User-Agent") || "Unknown",
      success,
      riskScore,
      sessionId: (request as any).sessionId,
      deviceFingerprint: this.generateDeviceFingerprint(request),
      metadata
    }

    return this.createSecurityEvent(eventData)
  }

  /**
   * Find security events with filters and pagination
   * @param options - Query options
   * @returns Paginated security events
   */
  async findEvents(options: SecurityEventQueryOptions = {}) {
    try {
      const {
        userId,
        eventType,
        success,
        ipAddress,
        severity,
        startDate,
        endDate,
        limit = 50,
        page = 1,
        sortBy = "createdAt",
        sortOrder = "desc"
      } = options

      const query: any = {}

      if (userId) query.userId = new Types.ObjectId(userId)
      if (eventType) query.eventType = eventType
      if (success !== undefined) query.success = success
      if (ipAddress) query.ipAddress = ipAddress
      if (severity) query.severity = severity

      if (startDate || endDate) {
        query.createdAt = {}
        if (startDate) query.createdAt.$gte = startDate
        if (endDate) query.createdAt.$lte = endDate
      }

      const sort: any = {}
      sort[sortBy] = sortOrder === "asc" ? 1 : -1

      const [events, total] = await Promise.all([
        this.securityEventModel
          .find(query)
          .sort(sort)
          .limit(limit)
          .skip((page - 1) * limit)
          .populate("userId", "email username")
          .exec(),
        this.securityEventModel.countDocuments(query)
      ])

      return {
        events,
        pagination: {
          total,
          page,
          limit,
          totalPages: Math.ceil(total / limit)
        }
      }
    } catch (error) {
      this.logger.error(`Failed to find security events: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Get failed login attempts for a user/IP in time window
   * @param identifier - Email, user ID, or IP address
   * @param timeWindow - Time window in milliseconds (default: 15 minutes)
   * @returns Number of failed attempts
   */
  async getFailedAttempts(identifier: string, timeWindow: number = 15 * 60 * 1000): Promise<number> {
    try {
      const cutoffTime = new Date(Date.now() - timeWindow)

      const query = {
        $or: [
          { email: identifier },
          { ipAddress: identifier },
          ...(Types.ObjectId.isValid(identifier) ? [{ userId: new Types.ObjectId(identifier) }] : [])
        ],
        eventType: { $in: [SecurityEventType.LOGIN_FAILED, SecurityEventType.LOGIN_BLOCKED] },
        success: false,
        createdAt: { $gte: cutoffTime }
      }

      return await this.securityEventModel.countDocuments(query)
    } catch (error) {
      this.logger.error(`Failed to get failed attempts: ${error.message}`, error.stack)
      return 0
    }
  }

  /**
   * Get security event statistics
   * @param days - Number of days to analyze (default: 30)
   * @returns Security statistics
   */
  async getSecurityStats(days: number = 30): Promise<SecurityEventStats> {
    try {
      const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000)

      const [
        totalEvents,
        successfulEvents,
        failedEvents,
        averageRiskScore,
        eventsByType,
        topRiskyIPs,
        suspiciousActivity
      ] = await Promise.all([
        // Total events
        this.securityEventModel.countDocuments({ createdAt: { $gte: startDate } }),

        // Successful events
        this.securityEventModel.countDocuments({
          createdAt: { $gte: startDate },
          success: true
        }),

        // Failed events
        this.securityEventModel.countDocuments({
          createdAt: { $gte: startDate },
          success: false
        }),

        // Average risk score
        this.securityEventModel
          .aggregate([
            { $match: { createdAt: { $gte: startDate }, riskScore: { $exists: true } } },
            { $group: { _id: null, avgRisk: { $avg: "$riskScore" } } }
          ])
          .then((result) => result[0]?.avgRisk || 0),

        // Events by type
        this.securityEventModel
          .aggregate([
            { $match: { createdAt: { $gte: startDate } } },
            { $group: { _id: "$eventType", count: { $sum: 1 } } }
          ])
          .then((results) =>
            results.reduce((acc, curr) => {
              acc[curr._id] = curr.count
              return acc
            }, {})
          ),

        // Top risky IPs
        this.securityEventModel
          .aggregate([
            { $match: { createdAt: { $gte: startDate }, riskScore: { $gt: 50 } } },
            {
              $group: {
                _id: "$ipAddress",
                count: { $sum: 1 },
                avgRiskScore: { $avg: "$riskScore" }
              }
            },
            { $sort: { avgRiskScore: -1 } },
            { $limit: 10 }
          ])
          .then((results) =>
            results.map((r) => ({
              ip: r._id,
              count: r.count,
              avgRiskScore: Math.round(r.avgRiskScore)
            }))
          ),

        // Suspicious activity
        this.securityEventModel
          .aggregate([
            {
              $match: {
                createdAt: { $gte: startDate },
                $or: [{ riskScore: { $gt: 70 } }, { eventType: SecurityEventType.SUSPICIOUS_ACTIVITY }]
              }
            },
            {
              $group: {
                _id: {
                  userId: "$userId",
                  email: "$email",
                  ipAddress: "$ipAddress"
                },
                eventCount: { $sum: 1 },
                maxRiskScore: { $max: "$riskScore" }
              }
            },
            { $sort: { maxRiskScore: -1, eventCount: -1 } },
            { $limit: 20 }
          ])
          .then((results) =>
            results.map((r) => ({
              userId: r._id.userId?.toString(),
              email: r._id.email,
              ipAddress: r._id.ipAddress,
              eventCount: r.eventCount,
              riskScore: r.maxRiskScore || 0
            }))
          )
      ])

      return {
        totalEvents,
        successfulEvents,
        failedEvents,
        averageRiskScore: Math.round(averageRiskScore),
        eventsByType,
        topRiskyIPs,
        suspiciousActivity
      }
    } catch (error) {
      this.logger.error(`Failed to get security stats: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Delete old security events
   * @param days - Delete events older than this many days
   * @returns Number of deleted events
   */
  async cleanupOldEvents(days: number = 90): Promise<number> {
    try {
      const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
      const result = await this.securityEventModel.deleteMany({
        createdAt: { $lt: cutoffDate }
      })

      this.logger.log(`Cleaned up ${result.deletedCount} old security events`)
      return result.deletedCount
    } catch (error) {
      this.logger.error(`Failed to cleanup old events: ${error.message}`, error.stack)
      throw error
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
   * Generate device fingerprint from request
   * @param request - HTTP request
   * @returns Device fingerprint
   */
  private generateDeviceFingerprint(request: Request): string {
    const userAgent = request.get("User-Agent") || ""
    const acceptLanguage = request.get("Accept-Language") || ""
    const acceptEncoding = request.get("Accept-Encoding") || ""

    // Simple fingerprint generation (in production, use more sophisticated method)
    return Buffer.from(`${userAgent}${acceptLanguage}${acceptEncoding}`).toString("base64")
  }

  /**
   * Calculate event severity based on type and success
   * @param eventType - Security event type
   * @param success - Whether event was successful
   * @param riskScore - Risk score if available
   * @returns Severity level
   */
  private calculateSeverity(
    eventType: SecurityEventType,
    success: boolean,
    riskScore?: number
  ): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
    // Critical events
    if (!success && [SecurityEventType.ACCOUNT_LOCKED, SecurityEventType.SUSPICIOUS_ACTIVITY].includes(eventType)) {
      return "CRITICAL"
    }

    // High risk events
    if (!success && [SecurityEventType.LOGIN_BLOCKED, SecurityEventType.TOKEN_REFRESH_FAILED].includes(eventType)) {
      return "HIGH"
    }

    // Risk score based severity
    if (riskScore !== undefined) {
      if (riskScore >= 80) return "CRITICAL"
      if (riskScore >= 60) return "HIGH"
      if (riskScore >= 30) return "MEDIUM"
    }

    // Medium events
    if (
      !success &&
      [
        SecurityEventType.LOGIN_FAILED,
        SecurityEventType.SIGNUP_FAILED,
        SecurityEventType.PASSWORD_RESET_REQUESTED
      ].includes(eventType)
    ) {
      return "MEDIUM"
    }

    return "LOW"
  }
}
