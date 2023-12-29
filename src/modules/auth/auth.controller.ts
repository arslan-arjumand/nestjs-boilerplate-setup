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
  Req,
  NotFoundException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
// @Decorators
import { GetUser } from 'src/decorators/get-user.decorator';
// @Dto
import {
  ForgotPasswordDto,
  GoogleSignInCredentialsDto,
  ResetPasswordDto,
  SignInCredentialsDto,
  SignupCredentialsDto,
  VerifyEmailToken,
  VerifyOtpDto,
} from './dto';
// @Entities
import { Users } from '../user/schema/user.schema';
// @Services
import { AuthService } from './service/auth.service';
// @Utils
import { generalResponse } from 'src/utils';
import { AvatarGenerator } from 'random-avatar-generator';

@ApiTags('Auth')
@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get()
  async statusAPI(@Res() response: Response) {
    try {
      generalResponse({
        response,
        message: 'Server is up and running',
        status: HttpStatus.OK,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  // ********** User Register Process ********** //
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

  @Post('otp-verify')
  async otpVerify(
    @Res() response: Response,
    @Body(ValidationPipe)
    otpVerifyDto: VerifyOtpDto,
  ) {
    try {
      const data = await this.authService.otpVerify(otpVerifyDto);

      generalResponse({
        response,
        message: `OTP verified`,
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  // ********** User Login Process ********** //
  @Post('admin-signin')
  async adminSignIn(
    @Res() response: Response,
    @Body(ValidationPipe) signInCredentialsDto: SignInCredentialsDto,
  ) {
    try {
      const data = await this.authService.adminSignIn(signInCredentialsDto);

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

  @Post('google-signin')
  async googleSignIn(
    @Res() response: Response,
    @Body(ValidationPipe)
    googleSignInCredentialsDto: GoogleSignInCredentialsDto,
  ) {
    try {
      const generator = new AvatarGenerator();

      const newUserDto = {
        ...googleSignInCredentialsDto,
        avatar: generator.generateRandomAvatar('avatar'),
      };

      const data = await this.authService.googleSignIn(newUserDto);

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

  @Get('verify-user')
  @ApiBearerAuth()
  @UseGuards(AuthGuard('validate_token'))
  async refreshToken(@Req() request: Request, @Res() response: Response) {
    const token = request['token'];
    const user = request['user'];

    if (token && user) {
      generalResponse({
        response,
        message: `User verified successfully`,
        status: HttpStatus.OK,
        data: {
          token,
          user,
        },
      });
    }
  }

  @Post('forgotPassword')
  async forgotPassword(
    @Req() req: Request,
    @Res() response: Response,
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ) {
    try {
      const data = await this.authService.forgotPassword(
        forgotPasswordDto,
        req,
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

  @Post('verify-email')
  async verifyEmailToken(
    @Res() response: Response,
    @Body(ValidationPipe)
    verifyEmailTokenDto: VerifyEmailToken,
  ) {
    try {
      const data = await this.authService.verifyEmailToken(verifyEmailTokenDto);

      if (data) {
        generalResponse({
          response,
          message: `Email verification successful`,
          status: HttpStatus.OK,
          data,
        });
      }
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }
}
