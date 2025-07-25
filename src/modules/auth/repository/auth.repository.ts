/**
 * Repository class for handling authentication-related operations.
 */
import { Injectable, UnauthorizedException } from "@nestjs/common"
import * as bcrypt from "bcrypt"
import { JwtService } from "@nestjs/jwt"
import { UserService } from "@/modules/user/service/user.service"
import config from "@/config"
import * as crypto from "crypto"

const { JWT_SECRET_TOKEN, JWT_REFRESH_TOKEN, JWT_SECRET_TOKEN_EXPIRATION, JWT_REFRESH_TOKEN_EXPIRATION } = config.JWT

@Injectable()
export class AuthRepository {
  constructor(
    private readonly userServices: UserService,
    public readonly jwtService: JwtService
  ) {}

  /**
   * Updates the refresh token for a user.
   * @param refreshToken - The new refresh token.
   * @param id - The ID of the user.
   * @returns A promise that resolves to the updated user.
   */
  async updateRefreshTokenInUser(refreshToken: string | null, id: string) {
    let hashedRefreshToken: string | null = null
    if (refreshToken) {
      hashedRefreshToken = await bcrypt.hash(refreshToken, 12) // Increased salt rounds
    }

    return this.userServices.update(
      { _id: id },
      {
        refresh_token: hashedRefreshToken
      }
    )
  }

  /**
   * Generates an access token for a user with enhanced metadata
   * @param id - The ID of the user.
   * @param expiresIn - The expiration time for the token (optional).
   * @param deviceInfo - Device information for tracking (optional).
   * @returns A promise that resolves to the access token.
   */
  async getAccessToken(id: string, expiresIn?: string, deviceInfo?: string) {
    // Decode base64 encoded private key
    const privateKey = Buffer.from(JWT_SECRET_TOKEN, "base64").toString("utf8")

    const payload = {
      _id: id,
      type: "access",
      iat: Math.floor(Date.now() / 1000),
      ...(deviceInfo && { device: deviceInfo })
    }

    return this.jwtService.sign(payload, {
      privateKey: privateKey,
      expiresIn: expiresIn || JWT_SECRET_TOKEN_EXPIRATION,
      algorithm: "RS256"
    })
  }

  /**
   * Generates a refresh token for a user with enhanced metadata
   * @param id - The ID of the user.
   * @param expiresIn - The expiration time for the token (optional).
   * @param deviceInfo - Device information for tracking (optional).
   * @returns A promise that resolves to the refresh token.
   */
  async getRefreshToken(id: string, expiresIn?: string, deviceInfo?: string) {
    // Decode base64 encoded private key
    const privateKey = Buffer.from(JWT_SECRET_TOKEN, "base64").toString("utf8")

    const payload = {
      _id: id,
      type: "refresh",
      iat: Math.floor(Date.now() / 1000),
      ...(deviceInfo && { device: deviceInfo })
    }

    return this.jwtService.sign(payload, {
      privateKey: privateKey,
      expiresIn: expiresIn || JWT_REFRESH_TOKEN_EXPIRATION,
      algorithm: "RS256"
    })
  }

  /**
   * Generates a secure password reset token (NOT a JWT)
   * @param email - The email of the user
   * @returns A secure random token
   */
  async generatePasswordResetToken(email: string): Promise<string> {
    const resetToken = crypto.randomBytes(32).toString("hex")
    const hashedToken = await bcrypt.hash(resetToken, 12)

    // Store hashed token with expiration (15 minutes for security)
    const expiresAt = new Date(Date.now() + config.SECURITY.PASSWORD_RESET_EXPIRY)

    await this.userServices.update(
      { email },
      {
        password_reset_token: hashedToken,
        password_reset_expires: expiresAt
      }
    )

    return resetToken // Return unhashed token for email
  }

  /**
   * Verifies the validity of an access token with enhanced security checks
   * @param token - The token to verify.
   * @returns The user associated with the token.
   * @throws UnauthorizedException if the token is invalid or expired.
   */
  async verifyAccessToken(token: string) {
    try {
      // Decode base64 encoded public key
      const publicKey = Buffer.from(JWT_REFRESH_TOKEN, "base64").toString("utf8")

      const decoded = this.jwtService.verify(token, {
        publicKey: publicKey,
        algorithms: ["RS256"]
      }) as any

      if (decoded.type !== "access") {
        throw new UnauthorizedException("Invalid token type")
      }

      // Check if token is not too old (additional security measure)
      const tokenAge = Math.floor(Date.now() / 1000) - decoded.iat
      const maxTokenAge = 24 * 60 * 60 // 24 hours in seconds

      if (tokenAge > maxTokenAge) {
        throw new UnauthorizedException("Token is too old")
      }

      // Find user by ID
      const user = await this.userServices.findOne({
        _id: decoded._id
      })

      if (!user) {
        throw new UnauthorizedException("User not found")
      }

      return user
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error
      }
      throw new UnauthorizedException("Invalid or expired token")
    }
  }

  /**
   * Verifies and uses a refresh token to generate new tokens with blacklist support
   * @param refreshToken - The refresh token
   * @param deviceInfo - Device information for new tokens (optional)
   * @returns New access and refresh tokens
   */
  async refreshTokens(refreshToken: string, deviceInfo?: string) {
    try {
      // Decode base64 encoded public key
      const publicKey = Buffer.from(JWT_REFRESH_TOKEN, "base64").toString("utf8")

      // Verify the refresh token
      const decoded = this.jwtService.verify(refreshToken, {
        publicKey: publicKey,
        algorithms: ["RS256"]
      }) as any

      if (decoded.type !== "refresh") {
        throw new UnauthorizedException("Invalid token type")
      }

      // Check token age for additional security
      const tokenAge = Math.floor(Date.now() / 1000) - decoded.iat
      const maxRefreshTokenAge = 30 * 24 * 60 * 60 // 30 days in seconds

      if (tokenAge > maxRefreshTokenAge) {
        throw new UnauthorizedException("Refresh token is too old")
      }

      // Find user
      const user: any = await this.userServices.findOne({
        _id: decoded._id
      })

      if (!user) {
        throw new UnauthorizedException("User not found")
      }

      // Verify the refresh token matches the stored one
      const isValidRefreshToken = await bcrypt.compare(refreshToken, user.refresh_token || "")

      if (!isValidRefreshToken) {
        throw new UnauthorizedException("Invalid refresh token")
      }

      // Extract device info from original token or use provided
      const tokenDeviceInfo = deviceInfo || decoded.device

      // Generate new tokens with device info
      const newAccessToken = await this.getAccessToken(user._id.toString(), undefined, tokenDeviceInfo)
      const newRefreshToken = await this.getRefreshToken(user._id.toString(), undefined, tokenDeviceInfo)

      // Update stored refresh token (refresh token rotation)
      await this.updateRefreshTokenInUser(newRefreshToken, user._id.toString())

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      }
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error
      }
      throw new UnauthorizedException("Invalid or expired refresh token")
    }
  }

  /**
   * Verifies password reset token
   * @param email - User email
   * @param token - Reset token
   * @returns Boolean indicating if token is valid
   */
  async verifyPasswordResetToken(email: string, token: string): Promise<boolean> {
    const user: any = await this.userServices.findOne({ email })

    if (!user || !user.password_reset_token || !user.password_reset_expires) {
      return false
    }

    // Check if token is expired
    if (new Date() > user.password_reset_expires) {
      // Clean up expired token
      await this.userServices.update(
        { email },
        {
          password_reset_token: null,
          password_reset_expires: null
        }
      )
      return false
    }

    // Verify token
    return await bcrypt.compare(token, user.password_reset_token)
  }

  /**
   * Clears password reset token after use
   * @param email - User email
   */
  async clearPasswordResetToken(email: string) {
    await this.userServices.update(
      { email },
      {
        password_reset_token: null,
        password_reset_expires: null
      }
    )
  }

  /**
   * Revokes all refresh tokens for a user (logout from all devices)
   * @param id - User ID
   */
  async revokeAllRefreshTokens(id: string) {
    await this.updateRefreshTokenInUser(null, id)
  }
}
