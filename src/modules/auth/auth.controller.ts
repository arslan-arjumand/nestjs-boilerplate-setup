import {
  Body,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
  UseInterceptors,
  ValidationPipe
} from "@nestjs/common"
import { AuthGuard } from "@nestjs/passport"
import { ApiTags, ApiBearerAuth } from "@nestjs/swagger"
import { Request, Response } from "express"
import { ClassSerializerInterceptor } from "@nestjs/common"

import {
  ForgotPasswordDto,
  RefreshTokenDto,
  ResetPasswordDto,
  SignInCredentialsDto,
  SignupCredentialsDto,
  VerifyEmailDto,
  ResendVerificationDto
} from "./dto"
import { AuthService } from "./service/auth.service"
import { GetUser, Roles } from "@/decorators"
import { Users } from "../user/schema/user.schema"
import { generalResponse } from "@/utils"
import { RedisTokenBlacklistService } from "./service/redis-token-blacklist.service"
import { UserRole } from "@/enums"
import config from "@/config"

@ApiTags("Auth")
@Controller("auth")
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly tokenBlacklistService: RedisTokenBlacklistService
  ) {}

  /**
   * @description Sign up a new user with email verification.
   * @method POST
   * @param signupCredentialsDto
   * @return Success message indicating verification email sent.
   */
  @Post("signup")
  async signUp(
    @Req() req: Request,
    @Res() response: Response,
    @Body(ValidationPipe) signupCredentialsDto: SignupCredentialsDto
  ) {
    try {
      const data = await this.authService.signUp(signupCredentialsDto, req)

      if (data.status && data.status !== HttpStatus.CREATED) {
        throw new HttpException(data.message, data.status)
      }

      generalResponse({
        response,
        message: data.message,
        status: data.status,
        data: null
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Verify user email with token.
   * @method POST
   * @param verifyEmailDto
   * @return Success message.
   */
  @Post("verify-email")
  async verifyEmail(
    @Req() req: Request,
    @Res() response: Response,
    @Body(ValidationPipe) verifyEmailDto: VerifyEmailDto
  ) {
    try {
      const data = await this.authService.verifyEmail(verifyEmailDto, req)

      if (data.status) {
        throw new HttpException(data.message, data.status)
      }

      generalResponse({
        response,
        message: data.message,
        status: data.status,
        data: null
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Resend email verification.
   * @method POST
   * @param resendVerificationDto
   * @return Success message.
   */
  @Post("resend-verification")
  async resendVerification(
    @Req() req: Request,
    @Res() response: Response,
    @Body(ValidationPipe) resendVerificationDto: ResendVerificationDto
  ) {
    try {
      const data = await this.authService.resendVerification(resendVerificationDto, req)

      if (data.status && data.status !== HttpStatus.OK) {
        throw new HttpException(data.message, data.status)
      }

      generalResponse({
        response,
        message: data.message,
        status: data.status,
        data: null
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Sign in a user with enhanced session tracking.
   * @method POST
   * @param signInCredentialsDto
   * @return An object containing the access token and user data.
   */
  @Post("signin")
  async signIn(
    @Req() req: Request,
    @Res() response: Response,
    @Body(ValidationPipe) signInCredentialsDto: SignInCredentialsDto
  ) {
    try {
      const data = await this.authService.signIn(signInCredentialsDto, req)

      // Set refresh token as httpOnly cookie
      response.cookie("refreshToken", data.refreshToken, {
        httpOnly: true,
        secure: config.SERVER.ENVIRONMENT === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      })

      generalResponse({
        response,
        message: "Session created successfully",
        status: HttpStatus.OK,
        data: { accessToken: data.accessToken, user: data.user }
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Refresh access token with session management.
   * @method POST
   * @param refreshTokenDto
   * @return New access token.
   */
  @Post("refresh-token")
  async refreshToken(
    @Req() req: Request,
    @Res() response: Response,
    @Body(ValidationPipe) refreshTokenDto: RefreshTokenDto
  ) {
    try {
      // Get refresh token from cookie or body
      const refreshToken = req.cookies?.refreshToken || refreshTokenDto.refresh_token

      if (!refreshToken) {
        throw new HttpException("Refresh token not provided", HttpStatus.BAD_REQUEST)
      }

      const tokens = await this.authService.refreshToken(refreshToken, req)

      // Update refresh token cookie
      response.cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: config.SERVER.ENVIRONMENT === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      })

      generalResponse({
        response,
        message: "Token refreshed successfully",
        status: HttpStatus.OK,
        data: { accessToken: tokens.accessToken }
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Send password reset email.
   * @method POST
   * @param forgotPasswordDto
   * @return Success message.
   */
  @Post("forgot-password")
  async forgotPassword(
    @Req() req: Request,
    @Res() response: Response,
    @Body(ValidationPipe) forgotPasswordDto: ForgotPasswordDto
  ) {
    try {
      const origin = req.get("origin") || `${req.protocol}://${req.get("host")}`
      const data = await this.authService.forgotPassword(forgotPasswordDto, origin, req)

      generalResponse({
        response,
        message: data.message,
        status: HttpStatus.OK,
        data: {}
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Reset password with session termination.
   * @method POST
   * @param resetPasswordDto
   * @return Success message.
   */
  @Post("reset-password")
  async resetPassword(
    @Req() req: Request,
    @Res() response: Response,
    @Body(ValidationPipe) resetPasswordDto: ResetPasswordDto
  ) {
    try {
      const data = await this.authService.resetPassword(resetPasswordDto, req)

      // Clear any existing refresh token cookie
      response.clearCookie("refreshToken")

      generalResponse({
        response,
        message: data.message,
        status: HttpStatus.OK,
        data: {}
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Get authenticated user details.
   * @method GET
   * @param user
   * @return User object.
   */
  @Get("me")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  async me(@Res() response: Response, @GetUser() user: Users) {
    generalResponse({
      response,
      message: "User details retrieved successfully",
      status: HttpStatus.OK,
      data: { user }
    })
  }

  /**
   * @description Sign out current session.
   * @method POST
   * @param user
   * @return Success message.
   */
  @Post("signout")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  async signOut(@Req() req: Request, @Res() response: Response, @GetUser() user: Users) {
    try {
      const token = req["token"] // Set by JWT strategy
      await this.authService.signOut(user.id, token, req)

      // Clear refresh token cookie
      response.clearCookie("refreshToken")

      generalResponse({
        response,
        message: "Signed out successfully",
        status: HttpStatus.OK,
        data: {}
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Sign out from all devices and sessions.
   * @method POST
   * @param user
   * @return Success message with session count.
   */
  @Post("signout-all")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  async signOutAll(@Req() req: Request, @Res() response: Response, @GetUser() user: Users) {
    try {
      const token = req["token"] // Set by JWT strategy
      await this.authService.signOutAllDevices(user.id, token, req)

      // Clear refresh token cookie
      response.clearCookie("refreshToken")

      generalResponse({
        response,
        message: "Signed out from all devices successfully",
        status: HttpStatus.OK,
        data: {}
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Get user's active sessions with device and location info.
   * @method GET
   * @param user
   * @return List of active sessions.
   */
  @Get("sessions")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  async getActiveSessions(@Res() response: Response, @GetUser() user: Users) {
    try {
      const sessionData = await this.authService.getUserSessions(user.id, false)

      generalResponse({
        response,
        message: "Active sessions retrieved successfully",
        status: HttpStatus.OK,
        data: sessionData
      })
    } catch (error) {
      throw new HttpException(
        error["message"] || "Failed to retrieve sessions",
        error["status"] || HttpStatus.INTERNAL_SERVER_ERROR
      )
    }
  }

  /**
   * @description Get detailed session statistics for the user.
   * @method GET
   * @param user
   * @return Session statistics including device breakdown and geographic info.
   */
  @Get("sessions/stats")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  async getSessionStats(@Res() response: Response, @GetUser() user: Users) {
    try {
      const stats = await this.authService.getUserSessionStats(user.id)

      generalResponse({
        response,
        message: "Session statistics retrieved successfully",
        status: HttpStatus.OK,
        data: stats
      })
    } catch (error) {
      throw new HttpException(
        error["message"] || "Failed to retrieve session statistics",
        error["status"] || HttpStatus.INTERNAL_SERVER_ERROR
      )
    }
  }

  /**
   * @description Terminate specific sessions by token identifiers.
   * @method POST
   * @param user
   * @param body - Contains array of token identifiers to blacklist
   * @return Number of tokens blacklisted.
   */
  @Post("logout-tokens")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  async logoutSpecificTokens(
    @Req() req: Request,
    @Res() response: Response,
    @GetUser() user: Users,
    @Body() body: { tokenIdentifiers: string[] }
  ) {
    try {
      const { tokenIdentifiers } = body

      if (!tokenIdentifiers || !Array.isArray(tokenIdentifiers) || tokenIdentifiers.length === 0) {
        throw new HttpException("Token identifiers array is required", HttpStatus.BAD_REQUEST)
      }

      const tokenBlacklistService = this.authService["tokenBlacklistService"] as RedisTokenBlacklistService
      const fullTokens = await tokenBlacklistService.getUserFullTokens(user.id)

      let blacklistedCount = 0

      for (const identifier of tokenIdentifiers) {
        const matchingToken = await this.findTokenByIdentifier(fullTokens, identifier)
        if (matchingToken) {
          await tokenBlacklistService.blacklistToken(matchingToken)
          blacklistedCount++
        }
      }

      generalResponse({
        response,
        message: `Successfully terminated ${blacklistedCount} sessions`,
        status: HttpStatus.OK,
        data: { blacklistedCount }
      })
    } catch (error) {
      throw new HttpException(
        error["message"] || "Failed to terminate sessions",
        error["status"] || HttpStatus.INTERNAL_SERVER_ERROR
      )
    }
  }

  /**
   * @description Get comprehensive security statistics and recent events.
   * @method GET
   * @param user
   * @return Security analytics including failed attempts, risk scores, and event history.
   */
  @Get("security/stats")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN)
  async getSecurityStats(@Res() response: Response, @GetUser() user: Users) {
    try {
      const stats = await this.authService.getSecurityStats(30) // Last 30 days

      generalResponse({
        response,
        message: "Security statistics retrieved successfully",
        status: HttpStatus.OK,
        data: stats
      })
    } catch (error) {
      throw new HttpException(
        error["message"] || "Failed to retrieve security statistics",
        error["status"] || HttpStatus.INTERNAL_SERVER_ERROR
      )
    }
  }

  /**
   * Helper method to find a full token by various identifiers
   * @param fullTokens - Array of full JWT tokens
   * @param identifier - Token identifier (can be prefix, timestamp, device info, etc.)
   * @returns Matching token or null
   */
  private async findTokenByIdentifier(fullTokens: string[], identifier: string): Promise<string | null> {
    const authRepository = this.authService["authRepository"]

    for (const token of fullTokens) {
      try {
        // Check if identifier matches token prefix
        if (token.includes(identifier)) {
          return token
        }

        // Decode token and check various fields
        const decoded = authRepository.jwtService.decode(token) as any
        if (decoded) {
          // Check if identifier matches issued timestamp
          if (decoded.iat && decoded.iat.toString().includes(identifier)) {
            return token
          }

          // Check if identifier matches device info
          if (decoded.device && decoded.device.includes(identifier)) {
            return token
          }

          // Check if identifier is a partial match of the token itself
          if (token.substring(0, 20).includes(identifier)) {
            return token
          }
        }
      } catch (error) {
        // Skip invalid tokens
        continue
      }
    }

    return null
  }
}
