import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose"
import { HydratedDocument, Document, Types } from "mongoose"

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

@Schema({
  collection: "security_events",
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
export class SecurityEvent extends Document {
  /**
   * Type of security event
   */
  @Prop({
    type: String,
    enum: Object.values(SecurityEventType),
    required: true,
    index: true
  })
  eventType: SecurityEventType

  /**
   * User ID associated with the event (if applicable)
   */
  @Prop({
    type: Types.ObjectId,
    ref: "Users",
    index: true
  })
  userId?: Types.ObjectId

  /**
   * User email (for events before user is resolved)
   */
  @Prop({
    type: String,
    index: true
  })
  email?: string

  /**
   * Client IP address
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
   * Whether the event was successful
   */
  @Prop({
    type: Boolean,
    required: true,
    index: true
  })
  success: boolean

  /**
   * Risk score calculated for this event (0-100)
   */
  @Prop({
    type: Number,
    min: 0,
    max: 100,
    index: true
  })
  riskScore?: number

  /**
   * Session ID if applicable
   */
  @Prop({
    type: String,
    index: true
  })
  sessionId?: string

  /**
   * Device fingerprint/identifier
   */
  @Prop({
    type: String
  })
  deviceFingerprint?: string

  /**
   * Geographic location data
   */
  @Prop({
    type: {
      country: String,
      region: String,
      city: String,
      timezone: String
    }
  })
  location?: {
    country: string
    region: string
    city: string
    timezone: string
  }

  /**
   * Additional metadata specific to the event
   */
  @Prop({
    type: Object,
    default: {}
  })
  metadata?: any

  /**
   * Event severity level
   */
  @Prop({
    type: String,
    enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    default: "LOW",
    index: true
  })
  severity: string

  /**
   * Whether this event triggered any automated responses
   */
  @Prop({
    type: Boolean,
    default: false
  })
  triggeredAutomatedResponse: boolean

  /**
   * Reference to related events (for correlation)
   */
  @Prop({
    type: [Types.ObjectId],
    ref: "SecurityEvent"
  })
  relatedEvents?: Types.ObjectId[]
}

export type SecurityEventDocument = HydratedDocument<SecurityEvent>
export const SecurityEventSchema = SchemaFactory.createForClass(SecurityEvent)

// Create compound indexes for efficient queries
SecurityEventSchema.index({ eventType: 1, timestamp: -1 })
SecurityEventSchema.index({ userId: 1, timestamp: -1 })
SecurityEventSchema.index({ ipAddress: 1, timestamp: -1 })
SecurityEventSchema.index({ success: 1, eventType: 1, timestamp: -1 })
SecurityEventSchema.index({ riskScore: -1, timestamp: -1 })
SecurityEventSchema.index({ severity: 1, timestamp: -1 })
