import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose"
import { HydratedDocument, Document } from "mongoose"
import { UserRole } from "@/enums"

/**
 * Represents a user in the system.
 */
@Schema({
  toJSON: {
    virtuals: true,
    /**
     * Transforms the document before converting it to JSON.
     * Removes the "_id" and "__v" fields from the JSON representation.
     * @param doc - The document being transformed.
     * @param ret - The transformed JSON representation of the document.
     * @returns The transformed JSON representation of the document.
     */
    transform: function (doc: any, ret: any) {
      delete ret._id
      delete ret.__v
      delete ret.password
      delete ret.refresh_token
      delete ret.password_reset_token
      delete ret.password_reset_expires
      return ret
    }
  },
  timestamps: true
})
export class Users extends Document {
  /**
   * The username of the user.
   */
  @Prop({
    type: "string",
    required: true
  })
  username: string

  /**
   * The email address of the user.
   */
  @Prop({
    type: "string",
    required: true,
    unique: true
  })
  email: string

  /**
   * The password of the user.
   * Defaults to an empty string if not provided.
   */
  @Prop({
    type: "string",
    required: false,
    default: ""
  })
  password: string

  /**
   * The refresh token for the user.
   */
  @Prop({
    type: String,
    required: false,
    default: null
  })
  refresh_token: string

  /**
   * The password reset token for the user.
   */
  @Prop({
    type: String,
    required: false,
    default: null
  })
  password_reset_token: string

  /**
   * The expiration time for the password reset token.
   */
  @Prop({
    type: Date,
    required: false,
    default: null
  })
  password_reset_expires: Date

  /**
   * Account verification status
   */
  @Prop({
    type: Boolean,
    default: false
  })
  is_verified: boolean

  /**
   * Email verification token
   */
  @Prop({
    type: String,
    required: false,
    default: null
  })
  email_verification_token: string

  /**
   * Email verification token expiry
   */
  @Prop({
    type: Date,
    required: false,
    default: null
  })
  email_verification_expires: Date

  /**
   * Failed login attempts counter
   */
  @Prop({
    type: Number,
    default: 0
  })
  failed_login_attempts: number

  /**
   * Account lock until timestamp
   */
  @Prop({
    type: Date,
    required: false,
    default: null
  })
  locked_until: Date

  /**
   * User role for access control
   */
  @Prop({
    type: String,
    enum: UserRole,
    default: UserRole.USER
  })
  role: UserRole
}

/**
 * Represents a hydrated user document.
 */
export type UsersDocument = HydratedDocument<Users>

/**
 * The Mongoose schema for the Users collection.
 */
export const UsersSchema = SchemaFactory.createForClass(Users)
