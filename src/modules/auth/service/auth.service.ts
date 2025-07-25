import { BadRequestException, HttpStatus, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common"
import { UserService } from "@/modules/user/service/user.service"
import {
  ForgotPasswordDto,
  ResetPasswordDto,
  SignInCredentialsDto,
  SignupCredentialsDto,
  VerifyEmailDto,
  ResendVerificationDto
} from "@/modules/auth/dto"
import { AuthRepository } from "@/modules/auth/repository/auth.repository"
import { compareHashValue, getHashValue } from "@/utils"
import { EmailService } from "@/modules/email/email.service"
import { RedisTokenBlacklistService } from "@/modules/auth/service/redis-token-blacklist.service"
import { SecurityLoggerService, SecurityEventType } from "@/modules/auth/service/security-logger.service"
import { SessionManagerService } from "@/modules/auth/service/session-manager.service"
import { Request } from "express"
import * as crypto from "crypto"
import config from "@/config"

const { MAX_LOGIN_ATTEMPTS, ACCOUNT_LOCK_TIME, MIN_PASSWORD_LENGTH } = config.SECURITY

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly userService: UserService,
    private readonly emailService: EmailService,
    private readonly tokenBlacklistService: RedisTokenBlacklistService,
    private readonly securityLogger: SecurityLoggerService,
    private readonly sessionManager: SessionManagerService
  ) {}

  /**
   * Sign up a new user with email verification
   * @param signupCredentialsDto - The signup credentials of the user
   * @param request - HTTP request object for logging
   * @returns Success message indicating verification email sent
   */
  async signUp(signupCredentialsDto: SignupCredentialsDto, request?: Request) {
    const { password, email, username } = signupCredentialsDto

    // Check if user already exists
    const existingUser = await this.userService.findOne({ email })
    if (existingUser) {
      // Log failed signup attempt
      if (request) {
        await this.securityLogger.logSecurityEvent(SecurityEventType.SIGNUP_FAILED, request, undefined, email, false, {
          reason: "User already exists"
        })
      }
      return { status: HttpStatus.CONFLICT, message: "User already exists" }
    }

    // Validate password strength
    if (!this.isPasswordStrong(password)) {
      return {
        status: HttpStatus.BAD_REQUEST,
        message:
          "Password must contain at least 8 characters, including uppercase, lowercase, number and special character"
      }
    }

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString("hex")
    const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now

    // Hash password
    const hashPassword = await getHashValue(password)

    // Create user data with verification fields
    const userData = {
      ...signupCredentialsDto,
      password: hashPassword,
      email_verification_token: verificationToken,
      email_verification_expires: verificationExpiry,
      is_verified: false
    }

    const data = await this.userService.create(userData)

    if (data) {
      try {
        // Send verification email
        await this.emailService.sendVerificationEmail(email, username, verificationToken)

        // Log successful signup attempt (but account not yet verified)
        if (request) {
          await this.securityLogger.logSecurityEvent(
            SecurityEventType.SIGNUP_SUCCESS,
            request,
            data._id as string,
            email,
            true,
            {
              reason: "Account created, verification email sent"
            }
          )
        }

        return {
          status: HttpStatus.CREATED,
          message: "Account created successfully. Please check your email to verify your account."
        }
      } catch (error) {
        // If email fails, we should probably delete the user or handle this gracefully
        console.error("Failed to send verification email:", error)

        // Log email sending failure
        if (request) {
          await this.securityLogger.logSecurityEvent(
            SecurityEventType.SIGNUP_FAILED,
            request,
            data._id as string,
            email,
            false,
            {
              reason: "Failed to send verification email"
            }
          )
        }

        return {
          status: HttpStatus.INTERNAL_SERVER_ERROR,
          message: "Account created but failed to send verification email. Please contact support."
        }
      }
    }

    return { status: HttpStatus.BAD_REQUEST, message: "Something went wrong" }
  }

  /**
   * Verify user email with token
   * @param verifyEmailDto - The verification token
   * @param request - HTTP request object for logging
   * @returns Success message or error
   */
  async verifyEmail(verifyEmailDto: VerifyEmailDto, request?: Request) {
    const { token } = verifyEmailDto

    // Find user with valid verification token
    const user = await this.userService.findOne({
      email_verification_token: token,
      email_verification_expires: { $gt: new Date() }
    })

    if (!user) {
      // Log failed verification attempt
      if (request) {
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.LOGIN_FAILED, // Using LOGIN_FAILED for verification failure
          request,
          undefined,
          undefined,
          false,
          { reason: "Invalid or expired verification token" }
        )
      }
      return {
        status: HttpStatus.BAD_REQUEST,
        message: "Invalid or expired verification token"
      }
    }

    // Update user as verified and clear verification fields
    await this.userService.update(
      { _id: user._id },
      {
        is_verified: true,
        email_verification_token: null,
        email_verification_expires: null
      }
    )

    // Log successful verification
    if (request) {
      await this.securityLogger.logSecurityEvent(
        SecurityEventType.LOGIN_SUCCESS, // Using LOGIN_SUCCESS for verification success
        request,
        user._id as string,
        (user as any).email,
        true,
        { reason: "Email verified successfully" }
      )
    }

    return {
      status: HttpStatus.OK,
      message: "Email verified successfully. You can now login to your account."
    }
  }

  /**
   * Resend email verification
   * @param resendVerificationDto - The email to resend verification to
   * @param request - HTTP request object for logging
   * @returns Success message or error
   */
  async resendVerification(resendVerificationDto: ResendVerificationDto, request?: Request) {
    const { email } = resendVerificationDto

    // Find unverified user
    const user = await this.userService.findOne({
      email,
      is_verified: false
    })

    if (!user) {
      // Log failed resend attempt
      if (request) {
        await this.securityLogger.logSecurityEvent(SecurityEventType.LOGIN_FAILED, request, undefined, email, false, {
          reason: "User not found or already verified"
        })
      }
      return {
        status: HttpStatus.BAD_REQUEST,
        message: "User not found or already verified"
      }
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(32).toString("hex")
    const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now

    // Update user with new token
    await this.userService.update(
      { _id: user._id },
      {
        email_verification_token: verificationToken,
        email_verification_expires: verificationExpiry
      }
    )

    try {
      // Send verification email
      await this.emailService.sendResendVerificationEmail(email, (user as any).username, verificationToken)

      // Log successful resend
      if (request) {
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.SIGNUP_SUCCESS,
          request,
          user._id as string,
          email,
          true,
          { reason: "Verification email resent successfully" }
        )
      }

      return {
        status: HttpStatus.OK,
        message: "Verification email sent successfully. Please check your email."
      }
    } catch (error) {
      console.error("Failed to resend verification email:", error)

      // Log email sending failure
      if (request) {
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.LOGIN_FAILED,
          request,
          user._id as string,
          email,
          false,
          { reason: "Failed to resend verification email" }
        )
      }

      return {
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        message: "Failed to send verification email. Please try again later."
      }
    }
  }

  /**
   * Sign in a user with enhanced session tracking and risk assessment
   * @param signInCredentialsDto - The sign-in credentials of the user
   * @param request - HTTP request object for logging and risk assessment
   * @returns An object containing the access token, refresh token, and user data
   */
  async signIn(signInCredentialsDto: SignInCredentialsDto, request?: Request) {
    const { email, password } = signInCredentialsDto

    const user: any = await this.userService.findOne({ email })

    // Assess risk before processing
    if (request) {
      const riskAssessment = this.securityLogger.assessRisk(request)
      if (riskAssessment.riskScore > 70) {
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.SUSPICIOUS_ACTIVITY,
          request,
          undefined,
          email,
          false,
          {
            riskScore: riskAssessment.riskScore,
            reasons: riskAssessment.reasons
          }
        )
        throw new UnauthorizedException("Suspicious activity detected")
      }
    }

    // Check if account is locked (only if user exists)
    if (user && user.locked_until && new Date() < user.locked_until) {
      const lockTimeRemaining = Math.ceil((user.locked_until.getTime() - Date.now()) / 60000)

      if (request) {
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.LOGIN_BLOCKED,
          request,
          user._id.toString(),
          email,
          false,
          { lockTimeRemaining }
        )
      }

      throw new UnauthorizedException(`Account locked. Try again in ${lockTimeRemaining} minutes`)
    }

    // Validate password (compare even if user doesn't exist to prevent timing attacks)
    const isValidPassword = user ? await compareHashValue(password, user.password) : false

    if (!user || !isValidPassword) {
      // Increment failed attempts only if user exists
      if (user) {
        await this.handleFailedLogin(user)
      }

      // Log failed login attempt
      if (request) {
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.LOGIN_FAILED,
          request,
          user?._id?.toString(),
          email,
          false,
          { reason: !user ? "User not found" : "Invalid password" }
        )
      }

      // Same error message regardless of user existence
      throw new BadRequestException("Invalid email or password")
    }

    // Check if email is verified
    if (!user.is_verified) {
      // Log failed login attempt due to unverified email
      if (request) {
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.LOGIN_FAILED,
          request,
          user._id.toString(),
          email,
          false,
          { reason: "Email not verified" }
        )
      }

      throw new UnauthorizedException(
        "Please verify your email before logging in. Check your inbox for the verification link."
      )
    }

    // Reset failed attempts on successful login
    await this.resetFailedAttempts(user._id.toString())

    const userId = user._id.toString()

    // Generate tokens with device info
    const deviceInfo = this.extractDeviceInfo(request)
    const accessToken = await this.authRepository.getAccessToken(userId, undefined, deviceInfo)
    const refreshToken = await this.authRepository.getRefreshToken(userId, undefined, deviceInfo)

    // Store refresh token in user record
    await this.authRepository.updateRefreshTokenInUser(refreshToken, userId)

    // Create session in MongoDB
    let sessionId: string | undefined
    if (request) {
      try {
        const session = await this.sessionManager.createSession(userId, request, await getHashValue(refreshToken), {
          loginMethod: "credentials",
          deviceInfo,
          riskScore: request ? this.securityLogger.assessRisk(request).riskScore : 0
        })
        sessionId = session.sessionId
      } catch (error) {
        console.warn("Failed to create session in MongoDB:", error.message)
      }
    }

    // Track the new access token in Redis
    await this.tokenBlacklistService.trackToken(accessToken, userId)

    // Log successful login
    if (request) {
      await this.securityLogger.logSecurityEvent(SecurityEventType.LOGIN_SUCCESS, request, userId, email, true, {
        sessionId,
        deviceInfo
      })
    }

    // Return both tokens (refresh token will be set as httpOnly cookie in controller)
    return { accessToken, refreshToken, user }
  }

  /**
   * Refresh access token with session management
   * @param refreshToken - The refresh token
   * @param request - HTTP request object for logging
   * @returns New tokens
   */
  async refreshToken(refreshToken: string, request?: Request) {
    try {
      // First, check if the refresh token itself is blacklisted
      const isRefreshTokenBlacklisted = await this.tokenBlacklistService.isTokenBlacklisted(refreshToken)
      if (isRefreshTokenBlacklisted) {
        if (request) {
          await this.securityLogger.logSecurityEvent(
            SecurityEventType.TOKEN_REFRESH_FAILED,
            request,
            undefined,
            undefined,
            false,
            { error: "Refresh token is blacklisted" }
          )
        }
        throw new UnauthorizedException("Refresh token has been revoked")
      }

      // Extract user ID from current refresh token to get their active tokens
      const currentDecoded = this.authRepository.jwtService.decode(refreshToken) as any
      const userId = currentDecoded?._id

      // Get current active access tokens before generating new ones
      let currentAccessTokens: string[] = []
      if (userId) {
        try {
          const userTokens = await this.tokenBlacklistService.getUserTokens(userId)
          currentAccessTokens = await this.getFullTokensFromTokenInfo(userTokens, userId)
        } catch (error) {
          console.warn("Failed to get current access tokens for user:", userId, error)
        }
      }

      // Generate new tokens with device info
      const deviceInfo = this.extractDeviceInfo(request)
      const tokens = await this.authRepository.refreshTokens(refreshToken, deviceInfo)

      // Extract user ID from the new access token
      const decoded = this.authRepository.jwtService.decode(tokens.accessToken) as any

      if (decoded && decoded._id) {
        // Blacklist all current access tokens before tracking the new one
        // This prevents the race condition where old and new tokens are both valid
        for (const oldToken of currentAccessTokens) {
          try {
            await this.tokenBlacklistService.blacklistToken(oldToken)
          } catch (error) {
            console.warn("Failed to blacklist old access token:", error)
          }
        }

        // Track the new access token
        try {
          await this.tokenBlacklistService.trackToken(tokens.accessToken, decoded._id)
        } catch (error) {
          console.error("Critical: Failed to track new access token:", error)
          // In case of tracking failure, we should blacklist the new token to prevent untracked tokens
          await this.tokenBlacklistService.blacklistToken(tokens.accessToken)
          throw new UnauthorizedException("Token generation failed, please try again")
        }

        // Update session activity if session ID is available
        const sessionId = (request as any)?.sessionId
        if (sessionId) {
          try {
            await this.sessionManager.updateSessionActivity(sessionId, request)

            // Update session with new refresh token hash
            const newRefreshTokenHash = await getHashValue(tokens.refreshToken)
            await this.sessionManager.getSessionById(sessionId) // This could be enhanced to update
          } catch (error) {
            console.warn("Failed to update session activity:", error.message)
          }
        }

        // Log successful token refresh
        if (request) {
          await this.securityLogger.logSecurityEvent(
            SecurityEventType.TOKEN_REFRESH,
            request,
            decoded._id,
            undefined,
            true,
            {
              sessionId,
              deviceInfo
            }
          )
        }
      }

      return tokens
    } catch (error) {
      // Log failed token refresh
      if (request) {
        await this.securityLogger.logSecurityEvent(
          SecurityEventType.TOKEN_REFRESH_FAILED,
          request,
          undefined,
          undefined,
          false,
          { error: error.message }
        )
      }
      throw error
    }
  }

  /**
   * Send a secure password reset email
   * @param forgotPasswordDto - The forgot password DTO
   * @param origin - The origin URL
   * @param request - HTTP request object for logging
   * @returns Email send result
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto, origin: string, request?: Request) {
    const { email } = forgotPasswordDto

    const user = await this.userService.findOne({ email })

    // Log password reset request
    if (request) {
      await this.securityLogger.logSecurityEvent(
        SecurityEventType.PASSWORD_RESET_REQUESTED,
        request,
        user?._id?.toString(),
        email,
        !!user
      )
    }

    if (!user) {
      // Don't reveal if email exists or not for security
      return { message: "If the email exists, a reset link has been sent" }
    }

    // Generate secure reset token (not JWT)
    const resetToken = await this.authRepository.generatePasswordResetToken(email)

    const resetUrl = `${origin}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`
    const message = `
      You requested a password reset. Click the link below to reset your password:
      ${resetUrl}
      
      This link will expire in 15 minutes.
      If you didn't request this, please ignore this email.
    `

    try {
      await this.emailService.sendEmail(email, "Password Reset Request", message)
      return { message: "Password reset link sent successfully" }
    } catch (error) {
      throw new BadRequestException("Failed to send reset email")
    }
  }

  /**
   * Reset password with session termination
   * @param resetPasswordDto - The reset password DTO
   * @param request - HTTP request object for logging
   * @returns Success message
   */
  async resetPassword(resetPasswordDto: ResetPasswordDto, request?: Request) {
    const { email, password, token } = resetPasswordDto

    // Validate password strength
    if (!this.isPasswordStrong(password)) {
      throw new BadRequestException(
        "Password must contain at least 8 characters, including uppercase, lowercase, number and special character"
      )
    }

    // Verify reset token
    const isValidToken = await this.authRepository.verifyPasswordResetToken(email, token)
    if (!isValidToken) {
      throw new BadRequestException("Invalid or expired reset token")
    }

    const user = await this.userService.findOne({ email })
    if (!user) {
      throw new BadRequestException("User not found")
    }

    const userId = (user as any)._id.toString()

    // Update password
    const hashPassword = await getHashValue(password)
    await this.userService.update(
      { email },
      {
        password: hashPassword,
        failed_login_attempts: 0,
        locked_until: null
      }
    )

    // Clear reset token
    await this.authRepository.clearPasswordResetToken(email)

    // Revoke all refresh tokens for security
    await this.authRepository.revokeAllRefreshTokens(userId)

    // Terminate all sessions due to password reset
    if (request) {
      try {
        await this.sessionManager.terminateAllUserSessions(userId, "PASSWORD_RESET", undefined, request)
      } catch (error) {
        console.warn("Failed to terminate sessions on password reset:", error.message)
      }
    }

    // Log successful password reset
    if (request) {
      await this.securityLogger.logSecurityEvent(
        SecurityEventType.PASSWORD_RESET_COMPLETED,
        request,
        userId,
        email,
        true
      )
    }

    return { message: "Password reset successfully" }
  }

  /**
   * Sign out a user with session termination
   * @param id - The ID of the user
   * @param token - The current access token to blacklist
   * @param request - HTTP request object for logging
   */
  async signOut(id: string, token?: string, request?: Request) {
    // Blacklist current access token
    if (token) {
      await this.tokenBlacklistService.blacklistToken(token)
    }

    // Terminate current session
    const sessionId = (request as any)?.sessionId
    if (sessionId) {
      try {
        await this.sessionManager.terminateSession(sessionId, "USER_LOGOUT", request)
      } catch (error) {
        console.warn("Failed to terminate session on logout:", error.message)
      }
    }

    // Log logout event
    if (request) {
      await this.securityLogger.logSecurityEvent(SecurityEventType.LOGOUT, request, id, undefined, true, {
        sessionId
      })
    }

    return this.authRepository.updateRefreshTokenInUser(null, id)
  }

  /**
   * Sign out from all devices with session management
   * @param id - The ID of the user
   * @param token - The current access token to blacklist
   * @param request - HTTP request object for logging
   */
  async signOutAllDevices(id: string, token?: string, request?: Request) {
    // Blacklist current access token
    if (token) {
      await this.tokenBlacklistService.blacklistToken(token)
    }

    // Blacklist all tokens for this user
    await this.tokenBlacklistService.blacklistAllUserTokens(id)

    // Terminate all sessions
    const currentSessionId = (request as any)?.sessionId
    try {
      await this.sessionManager.terminateAllUserSessions(id, "LOGOUT_ALL", currentSessionId, request)
    } catch (error) {
      console.warn("Failed to terminate all sessions:", error.message)
    }

    // Log logout all event
    if (request) {
      await this.securityLogger.logSecurityEvent(SecurityEventType.LOGOUT_ALL, request, id, undefined, true, {
        currentSessionId
      })
    }

    return this.authRepository.revokeAllRefreshTokens(id)
  }

  /**
   * Get user details
   * @param condition - Query condition
   */
  async getUser(condition: object) {
    return await this.userService.findOne(condition)
  }

  /**
   * Get user sessions (delegated to SessionManager)
   * @param userId - User ID
   * @param includeDetails - Whether to include detailed info
   * @returns User sessions
   */
  async getUserSessions(userId: string, includeDetails: boolean = false) {
    return await this.sessionManager.getUserSessions(userId, includeDetails)
  }

  /**
   * Get user session statistics
   * @param userId - User ID
   * @returns Session statistics
   */
  async getUserSessionStats(userId: string) {
    return await this.sessionManager.getUserSessionStats(userId)
  }

  /**
   * Get security statistics
   * @param days - Number of days to analyze
   * @returns Security statistics
   */
  async getSecurityStats(days: number = 30) {
    return await this.securityLogger.getSecurityStats(days)
  }

  /**
   * Handle failed login attempts
   * @param user - The user object
   */
  private async handleFailedLogin(user: any) {
    const attempts = user.failed_login_attempts + 1

    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      await this.userService.update(
        { _id: user._id },
        {
          failed_login_attempts: attempts,
          locked_until: new Date(Date.now() + ACCOUNT_LOCK_TIME)
        }
      )
    } else {
      await this.userService.update({ _id: user._id }, { failed_login_attempts: attempts })
    }
  }

  /**
   * Reset failed login attempts
   * @param userId - User ID
   */
  private async resetFailedAttempts(userId: string) {
    await this.userService.update(
      { _id: userId },
      {
        failed_login_attempts: 0,
        locked_until: null
      }
    )
  }

  /**
   * Validate password strength based on security requirements
   * @param password - Password to validate
   * @returns Boolean indicating if password is strong enough
   */
  private isPasswordStrong(password: string): boolean {
    const { MIN_PASSWORD_LENGTH, REQUIRE_UPPERCASE, REQUIRE_LOWERCASE, REQUIRE_NUMBERS, REQUIRE_SPECIAL_CHARS } =
      config.SECURITY

    if (password.length < MIN_PASSWORD_LENGTH) return false
    if (REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) return false
    if (REQUIRE_LOWERCASE && !/[a-z]/.test(password)) return false
    if (REQUIRE_NUMBERS && !/\d/.test(password)) return false
    if (REQUIRE_SPECIAL_CHARS && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) return false

    return true
  }

  /**
   * Helper method to extract full tokens from token info
   * @param tokenInfos - Array of token information
   * @param userId - User ID
   * @returns Array of full access tokens
   */
  private async getFullTokensFromTokenInfo(
    tokenInfos: Array<{ token: string; expiresAt?: Date; issuedAt?: Date; deviceInfo?: string }>,
    userId: string
  ): Promise<string[]> {
    try {
      // Get all user tokens from Redis directly
      const fullTokens = await this.tokenBlacklistService.getUserFullTokens(userId)
      return fullTokens.filter((token) => {
        try {
          const decoded = this.authRepository.jwtService.decode(token) as any
          return decoded && decoded.type === "access" // Only return access tokens
        } catch {
          return false
        }
      })
    } catch (error) {
      console.warn("Failed to get full tokens for user:", userId, error)
      return []
    }
  }

  /**
   * Extract device information from request
   * @param request - HTTP request
   * @returns Device info string
   */
  private extractDeviceInfo(request?: Request): string | undefined {
    if (!request) return undefined

    const userAgent = request.get("User-Agent") || ""

    // Simple device detection (in production, use ua-parser-js)
    if (userAgent.toLowerCase().includes("mobile")) return "mobile"
    if (userAgent.toLowerCase().includes("tablet")) return "tablet"
    if (userAgent.toLowerCase().includes("desktop")) return "desktop"

    return "unknown"
  }
}
