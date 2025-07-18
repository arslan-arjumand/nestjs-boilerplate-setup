/**
 * Repository class for handling authentication-related operations.
 */
import { HttpException, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common"
import * as bcrypt from "bcrypt"
import { JwtService } from "@nestjs/jwt"
import { UserService } from "@/modules/user/service/user.service"
import config from "@/config"
import * as crypto from "crypto"

const { JWT_SECRET_TOKEN, JWT_SECRET_REFRESH_TOKEN, JWT_TOKEN_EXPIRATION, JWT_REFRESH_TOKEN_EXPIRATION } = config.JWT

@Injectable()
export class AuthRepository {
  constructor(
    private readonly userServices: UserService,
    private readonly jwtService: JwtService
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
   * Generates an access token for a user.
   * @param id - The ID of the user.
   * @param expiresIn - The expiration time for the token (optional).
   * @returns A promise that resolves to the access token.
   */
  async getAccessToken(id: string, expiresIn?: string) {
    return this.jwtService.sign(
      {
        _id: id,
        type: "access",
        iat: Math.floor(Date.now() / 1000)
      },
      {
        secret: JWT_SECRET_TOKEN,
        expiresIn: expiresIn || JWT_TOKEN_EXPIRATION
      }
    )
  }

  /**
   * Generates a refresh token for a user.
   * @param id - The ID of the user.
   * @param expiresIn - The expiration time for the token (optional).
   * @returns A promise that resolves to the refresh token.
   */
  async getRefreshToken(id: string, expiresIn?: string) {
    return this.jwtService.sign(
      {
        _id: id,
        type: "refresh",
        iat: Math.floor(Date.now() / 1000)
      },
      {
        secret: JWT_SECRET_REFRESH_TOKEN,
        expiresIn: expiresIn || JWT_REFRESH_TOKEN_EXPIRATION
      }
    )
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
   * Verifies the validity of an access token.
   * @param token - The token to verify.
   * @returns The user associated with the token.
   * @throws UnauthorizedException if the token is invalid or expired.
   */
  async verifyAccessToken(token: string) {
    try {
      const decoded = this.jwtService.verify(token, {
        secret: JWT_SECRET_TOKEN
      }) as any

      if (decoded.type !== "access") {
        throw new UnauthorizedException("Invalid token type")
      }

      // Find user by ID (not email)
      const user = await this.userServices.findOne({
        _id: decoded._id
      })

      if (!user) {
        throw new UnauthorizedException("User not found")
      }

      return user
    } catch (error) {
      throw new UnauthorizedException("Invalid or expired token")
    }
  }

  /**
   * Verifies and uses a refresh token to generate new tokens
   * @param refreshToken - The refresh token
   * @returns New access and refresh tokens
   */
  async refreshTokens(refreshToken: string) {
    try {
      // Verify the refresh token
      const decoded = this.jwtService.verify(refreshToken, {
        secret: JWT_SECRET_REFRESH_TOKEN
      }) as any

      if (decoded.type !== "refresh") {
        throw new UnauthorizedException("Invalid token type")
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

      // Generate new tokens (refresh token rotation)
      const newAccessToken = await this.getAccessToken(user._id.toString())
      const newRefreshToken = await this.getRefreshToken(user._id.toString())

      // Update stored refresh token
      await this.updateRefreshTokenInUser(newRefreshToken, user._id.toString())

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      }
    } catch (error) {
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
