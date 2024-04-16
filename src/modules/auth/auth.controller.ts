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
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { GetUser } from 'src/decorators/get-user.decorator';
import {
  ForgotPasswordDto,
  ResetPasswordDto,
  SignInCredentialsDto,
  SignupCredentialsDto,
} from './dto';
import { Users } from '../user/schema/user.schema';
import { AuthService } from './service/auth.service';
import { generalResponse } from 'src/utils';
import { AvatarGenerator } from 'random-avatar-generator';

@ApiTags('Auth')
@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  constructor(private authService: AuthService) {}

  /**
   * @description Sign up a new user.
   * @method POST
   * @param signupCredentialsDto
   * @return An object containing the access token, refresh token, and user data.
   */
  @Post('signup')
  async signUp(
    @Res() response: Response,
    @Body(ValidationPipe) signupCredentialsDto: SignupCredentialsDto,
  ) {
    try {
      const generator = new AvatarGenerator();

      const newUserDto = {
        ...signupCredentialsDto,
        avatar: generator.generateRandomAvatar('avatar'),
      };

      const data = await this.authService.signUp(newUserDto);

      if (data && data['message'] && data['status']) {
        generalResponse({
          response,
          message: data['message'],
          status: data['status'],
        });
      } else {
        generalResponse({
          response,
          message: 'User created successfully',
          status: HttpStatus.CREATED,
          data,
        });
      }
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  /**
   * @description Sign in a user.
   * @method POST
   * @param signInCredentialsDto
   * @return An object containing the access token, refresh token, and user data.
   */
  @Post('signin')
  async signIn(
    @Res() response: Response,
    @Body(ValidationPipe) signInCredentialsDto: SignInCredentialsDto,
  ) {
    try {
      const data = await this.authService.signIn(signInCredentialsDto);

      generalResponse({
        response,
        message: `Session created successful`,
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  /**
   * @description Sign out a user.
   * @method GET
   * @param user
   * @return A message indicating that the session has expired.
   */
  @Get('logout')
  @ApiBearerAuth()
  @UseGuards(AuthGuard('validate_token'))
  async logout(@Res() response: Response, @GetUser() user: Users) {
    try {
      await this.authService.signOut(user.id);

      generalResponse({
        response,
        message: `Session expired successful`,
        status: HttpStatus.OK,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  /**
   * @description Get user details.
   * @method GET
   * @param user
   * @return User details.
   */
  @Get('get-user')
  @ApiBearerAuth()
  @UseGuards(AuthGuard('validate_token'))
  async getUserDetail(@Res() response: Response, @GetUser() user: Users) {
    try {
      const data = await this.authService.getUser({ _id: user.id });

      generalResponse({
        response,
        message: `User found successful`,
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  /**
   * @description Forgot password.
   * @method POST
   * @param forgotPasswordDto
   * @return A message indicating that the reset link has been sent.
   */
  @Post('forgotPassword')
  async forgotPassword(
    @Headers('origin') origin: any,
    @Res() response: Response,
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ) {
    try {
      const data = await this.authService.forgotPassword(
        forgotPasswordDto,
        origin,
      );

      if (data && data.messageId) {
        generalResponse({
          response,
          message: 'Reset link sent successfully',
          status: HttpStatus.OK,
        });
      }
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  /**
   * @description Reset password.
   * @method POST
   * @param resetPasswordDto
   * @return An object containing the updated user data.
   */
  @Post('reset-password')
  async resetPassword(
    @Res() response: Response,
    @Body(ValidationPipe)
    resetPasswordDto: ResetPasswordDto,
  ) {
    try {
      const data = await this.authService.resetPassword(resetPasswordDto);

      if (data) {
        generalResponse({
          response,
          message: `Password changed successful`,
          status: HttpStatus.OK,
          data,
        });
      }
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }
}
