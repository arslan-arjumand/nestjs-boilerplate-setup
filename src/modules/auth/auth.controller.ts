import {
  Post,
  Body,
  ValidationPipe,
  Controller,
  Get,
  UseGuards,
  UseInterceptors,
  ClassSerializerInterceptor,
  HttpStatus,
  HttpException,
  Res,
  Headers,
  Req
} from "@nestjs/common"
import { AuthGuard } from "@nestjs/passport"
import { Request, Response } from "express"
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger"
import { GetUser } from "@/decorators/get-user.decorator"
import { ForgotPasswordDto, ResetPasswordDto, SignInCredentialsDto, SignupCredentialsDto, RefreshTokenDto } from "./dto"
import { Users } from "../user/schema/user.schema"
import { AuthService } from "./service/auth.service"
import { generalResponse } from "@/utils"

@ApiTags("Auth")
@Controller("auth")
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  constructor(private authService: AuthService) {}

  /**
   * @description Sign up a new user.
   * @method POST
   * @param signupCredentialsDto
   * @return An object containing the access token and user data.
   */
  @Post("signup")
  async signUp(@Res() response: Response, @Body(ValidationPipe) signupCredentialsDto: SignupCredentialsDto) {
    try {
      const newUserDto = {
        ...signupCredentialsDto,
        avatar: "default-avatar.png"
      }

      const data = await this.authService.signUp(newUserDto)

      if (data && data["message"] && data["status"]) {
        generalResponse({
          response,
          message: data["message"],
          status: data["status"]
        })
      } else {
        // Set refresh token as httpOnly cookie
        response.cookie("refreshToken", data.refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        })

        generalResponse({
          response,
          message: "User created successfully",
          status: HttpStatus.CREATED,
          data: { accessToken: data.accessToken, user: data.user }
        })
      }
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Sign in a user.
   * @method POST
   * @param signInCredentialsDto
   * @return An object containing the access token and user data.
   */
  @Post("signin")
  async signIn(@Res() response: Response, @Body(ValidationPipe) signInCredentialsDto: SignInCredentialsDto) {
    try {
      const data = await this.authService.signIn(signInCredentialsDto)

      // Set refresh token as httpOnly cookie
      response.cookie("refreshToken", data.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
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
   * @description Refresh access token using refresh token.
   * @method POST
   * @return New access token.
   */
  @Post("refresh")
  async refreshToken(@Req() request: Request, @Res() response: Response) {
    try {
      const refreshToken = request.cookies["refreshToken"]

      if (!refreshToken) {
        throw new HttpException("No refresh token provided", HttpStatus.UNAUTHORIZED)
      }

      const tokens = await this.authService.refreshToken(refreshToken)

      // Set new refresh token as httpOnly cookie
      response.cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
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
      // Clear invalid refresh token
      response.clearCookie("refreshToken")
      throw new HttpException(error["message"], HttpStatus.UNAUTHORIZED)
    }
  }

  /**
   * @description Sign out a user.
   * @method POST
   * @param user
   * @return A message indicating that the session has expired.
   */
  @Post("logout")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  async logout(@Res() response: Response, @GetUser() user: Users) {
    try {
      await this.authService.signOut(user.id)

      // Clear refresh token cookie
      response.clearCookie("refreshToken")

      generalResponse({
        response,
        message: "Session expired successfully",
        status: HttpStatus.OK
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Sign out from all devices.
   * @method POST
   * @param user
   * @return A message indicating that all sessions have expired.
   */
  @Post("logout-all")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  async logoutAll(@Res() response: Response, @GetUser() user: Users) {
    try {
      await this.authService.signOutAllDevices(user.id)

      // Clear refresh token cookie
      response.clearCookie("refreshToken")

      generalResponse({
        response,
        message: "All sessions expired successfully",
        status: HttpStatus.OK
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Get user details.
   * @method GET
   * @param user
   * @return User details.
   */
  @Get("me")
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  async getUserDetail(@Res() response: Response, @GetUser() user: Users) {
    try {
      const data = await this.authService.getUser({ _id: user.id })

      generalResponse({
        response,
        message: "User found successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Forgot password.
   * @method POST
   * @param forgotPasswordDto
   * @return A message indicating that the reset link has been sent.
   */
  @Post("forgot-password")
  async forgotPassword(
    @Headers("origin") origin: any,
    @Res() response: Response,
    @Body() forgotPasswordDto: ForgotPasswordDto
  ) {
    try {
      const data = await this.authService.forgotPassword(forgotPasswordDto, origin)

      generalResponse({
        response,
        message: data.message,
        status: HttpStatus.OK
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description Reset password.
   * @method POST
   * @param resetPasswordDto
   * @return An object containing the success message.
   */
  @Post("reset-password")
  async resetPassword(@Res() response: Response, @Body(ValidationPipe) resetPasswordDto: ResetPasswordDto) {
    try {
      const data = await this.authService.resetPassword(resetPasswordDto)

      generalResponse({
        response,
        message: data.message,
        status: HttpStatus.OK
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }
}
