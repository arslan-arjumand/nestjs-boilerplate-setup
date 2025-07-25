import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose"
import { HydratedDocument, Document, Types } from "mongoose"

export enum SessionStatus {
  ACTIVE = "ACTIVE",
  EXPIRED = "EXPIRED",
  TERMINATED = "TERMINATED",
  REVOKED = "REVOKED"
}

export enum DeviceType {
  DESKTOP = "DESKTOP",
  MOBILE = "MOBILE",
  TABLET = "TABLET",
  UNKNOWN = "UNKNOWN"
}

@Schema({
  collection: "user_sessions",
  toJSON: {
    virtuals: true,
    transform: function (doc: any, ret: any) {
      delete ret._id
      delete ret.__v
      return ret
    }
  },
  timestamps: true
})
export class UserSession extends Document {
  /**
   * User who owns this session
   */
  @Prop({
    type: Types.ObjectId,
    ref: "Users",
    required: true,
    index: true
  })
  userId: Types.ObjectId

  /**
   * Unique session identifier
   */
  @Prop({
    type: String,
    required: true,
    unique: true,
    index: true
  })
  sessionId: string

  /**
   * Current session status
   */
  @Prop({
    type: String,
    enum: Object.values(SessionStatus),
    default: SessionStatus.ACTIVE,
    index: true
  })
  status: SessionStatus

  /**
   * IP address when session was created
   */
  @Prop({
    type: String,
    required: true,
    index: true
  })
  ipAddress: string

  /**
   * User agent string
   */
  @Prop({
    type: String,
    required: true
  })
  userAgent: string

  /**
   * Device information
   */
  @Prop({
    type: {
      deviceType: { type: String, enum: Object.values(DeviceType), default: DeviceType.UNKNOWN },
      browser: String,
      os: String,
      fingerprint: String
    }
  })
  device: {
    deviceType: DeviceType
    browser?: string
    os?: string
    fingerprint?: string
  }

  /**
   * Geographic location data
   */
  @Prop({
    type: {
      country: String,
      region: String,
      city: String,
      timezone: String,
      coordinates: {
        latitude: Number,
        longitude: Number
      }
    }
  })
  location?: {
    country: string
    region: string
    city: string
    timezone: string
    coordinates?: {
      latitude: number
      longitude: number
    }
  }

  /**
   * When the session was first created
   */
  @Prop({
    type: Date,
    default: Date.now
  })
  createdAt: Date

  /**
   * When the session was last accessed
   */
  @Prop({
    type: Date,
    default: Date.now,
    index: true
  })
  lastAccessedAt: Date

  /**
   * When the session expires
   */
  @Prop({
    type: Date
  })
  expiresAt: Date

  /**
   * When the session was terminated
   */
  @Prop({
    type: Date,
    index: true
  })
  terminatedAt?: Date

  /**
   * How the session was terminated
   */
  @Prop({
    type: String,
    enum: ["USER_LOGOUT", "ADMIN_REVOKED", "EXPIRED", "SECURITY_REVOKED", "TOKEN_REFRESH"]
  })
  terminationReason?: string

  /**
   * Number of requests made in this session
   */
  @Prop({
    type: Number,
    default: 0
  })
  requestCount: number

  /**
   * Current refresh token hash (for validation)
   */
  @Prop({
    type: String
  })
  refreshTokenHash?: string

  /**
   * Security flags
   */
  @Prop({
    type: {
      isSuspicious: { type: Boolean, default: false },
      riskScore: { type: Number, min: 0, max: 100, default: 0 },
      requiresMFA: { type: Boolean, default: false },
      isPrivileged: { type: Boolean, default: false }
    },
    default: {}
  })
  security: {
    isSuspicious: boolean
    riskScore: number
    requiresMFA: boolean
    isPrivileged: boolean
  }

  /**
   * Session metadata
   */
  @Prop({
    type: Object,
    default: {}
  })
  metadata?: any
}

export type UserSessionDocument = HydratedDocument<UserSession>
export const UserSessionSchema = SchemaFactory.createForClass(UserSession)

// Create compound indexes for efficient queries
UserSessionSchema.index({ userId: 1, status: 1, createdAt: -1 })
UserSessionSchema.index({ sessionId: 1, status: 1 })
UserSessionSchema.index({ ipAddress: 1, createdAt: -1 })
UserSessionSchema.index({ expiresAt: 1 }) // For cleanup jobs
UserSessionSchema.index({ "security.riskScore": -1, createdAt: -1 })

// TTL index for automatic cleanup of expired sessions (after 30 days)
UserSessionSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 })
