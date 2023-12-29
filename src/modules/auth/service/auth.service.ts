import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
// @Services
import { UserService } from './../../user/service/user.service';
// @Dto
import {
  CreateOtpDto,
  ForgotPasswordDto,
  GoogleSignInCredentialsDto,
  ResetPasswordDto,
  SignInCredentialsDto,
  SignupCredentialsDto,
  VerifyEmailToken,
  VerifyOtpDto,
} from '../dto';
// @Repositories
import { AuthRepository } from '../repository/auth.repository';
// @Utils
import { compareHashValue, getHashValue, randomNumber } from 'src/utils';
import * as moment from 'moment';
import { EmailService } from 'src/modules/email/email.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly userService: UserService,
    private readonly emailService: EmailService,
  ) {}

  async signUp(signupCredentialsDto: SignupCredentialsDto) {
    const { password } = signupCredentialsDto;

    const user = await this.userService.findOne({
      email: signupCredentialsDto.email,
    });

    if (user) {
      return { status: HttpStatus.CONFLICT, message: 'User already exists' };
    }

    const hashPassword = await getHashValue(password);

    // create password for user
    signupCredentialsDto.password = hashPassword;

    const data = await this.userService.create(signupCredentialsDto);

    if (data) {
      // create access and refresh token
      const accessToken = await this.authRepository.getAccessToken(data._id);
      const refreshToken = await this.authRepository.getRefreshToken(data._id);

      return { accessToken, refreshToken, user: data };
    }

    return { status: HttpStatus.BAD_REQUEST, message: 'Something went wrong' };

    // return this.createOtp({
    //   email: data['email'],
    // });
  }

  async createOtp(createOtpDto: CreateOtpDto) {
    const { email } = createOtpDto;
    // validate user
    const user = await this.userService.findOne({ email });
    if (!user) {
      throw new NotFoundException('User not exist');
    }

    // Check if current OTP has expired and if 2 minutes have passed since last OTP sent
    if (user['sms_otp_created_at'] && user['sms_otp_expires_at'] > new Date()) {
      const now = moment();
      const lastSent = moment(user['sms_otp_created_at']);
      const diffInMinutes = now.diff(lastSent, 'minutes');

      if (diffInMinutes < 2) {
        return { timeException: true, user };
      }
    }

    // send otp
    const otp = randomNumber(6);

    const otpCreatedAt = new Date();
    const otpExpiresAt = moment(otpCreatedAt).add(2, 'minutes').toDate();

    if (!otp) {
      throw new BadRequestException('Something is not good');
    }

    // save otp and its timestamps in DB
    const updatedUser = await this.userService.update(
      { _id: user.id },
      {
        sms_otp: otp,
        sms_otp_created_at: otpCreatedAt,
        sms_otp_expires_at: otpExpiresAt,
      },
    );

    return updatedUser;
  }

  async otpVerify(otpVerifyDto: VerifyOtpDto) {
    const { email, otp } = otpVerifyDto;
    // Validate user & OTP
    const user = await this.userService.findOne({
      email,
    });

    if (!user) {
      throw new BadRequestException('Enter a valid email');
    }
    if (user['sms_otp'] !== otp) {
      throw new BadRequestException('Enter a valid OTP');
    }

    await user.save();

    // create access and refresh token
    const accessToken = await this.authRepository.getAccessToken(user.id);
    const refreshToken = await this.authRepository.getRefreshToken(user.id);
    // update token for user
    await this.authRepository.updateRefreshTokenInUser(refreshToken, user.id);

    const createEmailToken = await this.authRepository.getRefreshToken(email);

    const message = `You link is Email: ${email} and Token: ${createEmailToken}`;

    const messageInfo = await this.emailService.sendEmail(
      email,
      'Confirm your email',
      message,
    );

    if (messageInfo && messageInfo.messageId) {
      return { accessToken, refreshToken, user };
    }
  }

  async adminSignIn(signInCredentialsDto: SignInCredentialsDto) {
    const { password } = signInCredentialsDto;
    // Find user
    const user = await this.userService.findOne({
      email: signInCredentialsDto.email,
      role: 'admin',
    });
    if (!user) {
      throw new ForbiddenException();
    }
    // Validate password
    const compareHash = await compareHashValue(password, user['password']);
    if (!compareHash) {
      throw new ForbiddenException();
    }
    // create tokens
    const accessToken = await this.authRepository.getAccessToken(user.id);
    const refreshToken = await this.authRepository.getRefreshToken(user.id);
    // Update user refresh token
    await this.authRepository.updateRefreshTokenInUser(refreshToken, user.id);

    return { accessToken, refreshToken, user };
  }

  async signIn(signInCredentialsDto: SignInCredentialsDto) {
    const { email, password } = signInCredentialsDto;
    // Find user
    const user: any = await this.userService.findOne({ email });

    if (!user) {
      throw new BadRequestException('Invalid credential');
    }

    // Validate password
    const compareHash = await compareHashValue(password, user['password']);

    if (!compareHash) {
      throw new BadRequestException('Invalid Credential');
    }
    // create tokens
    const accessToken = await this.authRepository.getAccessToken(user.id);
    const refreshToken = await this.authRepository.getRefreshToken(user.id);
    // Update user refresh token
    await this.authRepository.updateRefreshTokenInUser(refreshToken, user.id);

    return { accessToken, refreshToken, user };
  }

  async googleSignIn(googleSignInCredentialsDto: GoogleSignInCredentialsDto) {
    const { googleId, email } = googleSignInCredentialsDto;
    // Find user
    const findUserByEmail = await this.userService.findOne({
      email,
      googleId: '',
    });

    if (findUserByEmail) {
      throw new ConflictException(
        'Another account is associated with this email',
      );
    }

    const user: any = await this.userService.findOne({ googleId });

    if (user) {
      const accessToken = await this.authRepository.getAccessToken(user.id);
      const refreshToken = await this.authRepository.getRefreshToken(user.id);
      await this.authRepository.updateRefreshTokenInUser(refreshToken, user.id);

      return { accessToken, refreshToken, user };
    }

    const data = await this.userService.create(googleSignInCredentialsDto);

    // create tokens
    const accessToken = await this.authRepository.getAccessToken(data.id);
    const refreshToken = await this.authRepository.getRefreshToken(data.id);
    await this.authRepository.updateRefreshTokenInUser(refreshToken, data.id);

    return { accessToken, refreshToken, user: data };
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto, req: any) {
    const data = await this.userService.findOne({
      email: forgotPasswordDto.email,
    });

    if (!data) {
      throw new NotFoundException('Enter a valid email');
    }

    const createToken = await this.authRepository.getRefreshToken(
      forgotPasswordDto.email,
      '1h',
    );

    const link = `${req.headers['origin']}/reset-password?token=${createToken}&email=${forgotPasswordDto.email}`;

    const message = `Your Reset Password Link is:\n ${link}`;

    const messageInfo = await this.emailService.sendEmail(
      forgotPasswordDto.email,
      'Reset Password Link',
      message,
    );

    return messageInfo;
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { email, password, token } = resetPasswordDto;
    // Validate user & OTP
    const user = await this.userService.findOne({
      email,
    });
    if (!user) {
      throw new BadRequestException('Enter a valid email');
    }

    const verifyToken = await this.authRepository.verifyToken(token);

    if (verifyToken) {
      const hashPassword = await getHashValue(password);
      // create password for user
      user['password'] = hashPassword;
      await user.save();

      return user;
    }

    throw new BadRequestException('Please try again');
  }

  async signOut(id: string) {
    return this.authRepository.updateRefreshTokenInUser(null, id);
  }

  async getUser(condition: object) {
    return await this.userService.findOne(condition);
  }

  async getRefreshToken(token: string) {
    const userExist = await this.authRepository.getUserIfRefreshTokenMatches(
      token,
    );

    return await this.authRepository.getNewAccessAndRefreshToken(userExist.id);
  }

  async verifyEmailToken(verifyEmailTokenDto: VerifyEmailToken) {
    const { token, email } = verifyEmailTokenDto;
    // Validate user & OTP
    const user = await this.userService.findOne({
      email,
    });

    if (!user) {
      throw new BadRequestException('Enter a valid email');
    }

    const verifyToken = await this.authRepository.verifyToken(token);

    if (verifyToken) {
      user['isVerified'] = true;
      await user.save();

      return user;
    }

    throw new BadRequestException('Please try again');
  }
}
