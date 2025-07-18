import { BadRequestException, HttpStatus, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common"
import { UserService } from "./../../user/service/user.service"
import { ForgotPasswordDto, ResetPasswordDto, SignInCredentialsDto, SignupCredentialsDto } from "../dto"
import { AuthRepository } from "../repository/auth.repository"
import { compareHashValue, getHashValue } from "@/utils"
import { EmailService } from "@/modules/email/email.service"
import config from "@/config"

const { MAX_LOGIN_ATTEMPTS, ACCOUNT_LOCK_TIME, MIN_PASSWORD_LENGTH } = config.SECURITY

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly userService: UserService,
    private readonly emailService: EmailService
  ) {}

  /**
   * Sign up a new user
   * @param signupCredentialsDto - The signup credentials of the user
   * @returns An object containing the access token, refresh token, and user data
   */
  async signUp(signupCredentialsDto: SignupCredentialsDto) {
    const { password, email } = signupCredentialsDto

    // Check if user already exists
    const existingUser = await this.userService.findOne({ email })
    if (existingUser) {
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

    const hashPassword = await getHashValue(password)
    signupCredentialsDto.password = hashPassword

    const data = await this.userService.create(signupCredentialsDto)

    if (data) {
      // Generate tokens
      const accessToken = await this.authRepository.getAccessToken(data._id as string)
      const refreshToken = await this.authRepository.getRefreshToken(data._id as string)

      // Store refresh token
      await this.authRepository.updateRefreshTokenInUser(refreshToken, data._id as string)

      // Return both tokens (refresh token will be set as httpOnly cookie in controller)
      return { accessToken, refreshToken, user: data }
    }

    return { status: HttpStatus.BAD_REQUEST, message: "Something went wrong" }
  }

  /**
   * Sign in a user with account locking and rate limiting
   * @param signInCredentialsDto - The sign-in credentials of the user
   * @returns An object containing the access token, refresh token, and user data
   */
  async signIn(signInCredentialsDto: SignInCredentialsDto) {
    const { email, password } = signInCredentialsDto

    const user: any = await this.userService.findOne({ email })
    if (!user) {
      throw new BadRequestException("Invalid credentials")
    }

    // Check if account is locked
    if (user.locked_until && new Date() < user.locked_until) {
      const lockTimeRemaining = Math.ceil((user.locked_until.getTime() - Date.now()) / 60000)
      throw new UnauthorizedException(`Account locked. Try again in ${lockTimeRemaining} minutes`)
    }

    // Validate password
    const isValidPassword = await compareHashValue(password, user.password)

    if (!isValidPassword) {
      // Increment failed attempts
      await this.handleFailedLogin(user)
      throw new BadRequestException("Invalid credentials")
    }

    // Reset failed attempts on successful login
    await this.resetFailedAttempts(user._id.toString())

    // Generate tokens
    const accessToken = await this.authRepository.getAccessToken(user._id.toString())
    const refreshToken = await this.authRepository.getRefreshToken(user._id.toString())

    // Store refresh token
    await this.authRepository.updateRefreshTokenInUser(refreshToken, user._id.toString())

    // Return both tokens (refresh token will be set as httpOnly cookie in controller)
    return { accessToken, refreshToken, user }
  }

  /**
   * Refresh access token using refresh token
   * @param refreshToken - The refresh token
   * @returns New tokens
   */
  async refreshToken(refreshToken: string) {
    return await this.authRepository.refreshTokens(refreshToken)
  }

  /**
   * Send a secure password reset email
   * @param forgotPasswordDto - The forgot password DTO
   * @param origin - The origin URL
   * @returns Email send result
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto, origin: string) {
    const { email } = forgotPasswordDto

    const user = await this.userService.findOne({ email })
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
   * Reset password using secure token
   * @param resetPasswordDto - The reset password DTO
   * @returns Success message
   */
  async resetPassword(resetPasswordDto: ResetPasswordDto) {
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
    await this.authRepository.revokeAllRefreshTokens((user as any)._id.toString())

    return { message: "Password reset successfully" }
  }

  /**
   * Sign out a user
   * @param id - The ID of the user
   */
  async signOut(id: string) {
    return this.authRepository.updateRefreshTokenInUser(null, id)
  }

  /**
   * Sign out from all devices
   * @param id - The ID of the user
   */
  async signOutAllDevices(id: string) {
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
}
