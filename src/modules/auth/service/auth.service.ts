import {
  BadRequestException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { UserService } from './../../user/service/user.service';
import {
  ForgotPasswordDto,
  ResetPasswordDto,
  SignInCredentialsDto,
  SignupCredentialsDto,
} from '../dto';
import { AuthRepository } from '../repository/auth.repository';
import { compareHashValue, getHashValue } from 'src/utils';
import { EmailService } from 'src/modules/email/email.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly userService: UserService,
    private readonly emailService: EmailService,
  ) {}

  /**
   * Sign up a new user
   * @param signupCredentialsDto - The signup credentials of the user
   * @returns An object containing the access token, refresh token, and user data
   */
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
  }

  /**
   * Sign in a user
   * @param signInCredentialsDto - The sign-in credentials of the user
   * @returns An object containing the access token, refresh token, and user data
   * @throws BadRequestException if the credentials are invalid
   */
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

  /**
   * Send a password reset email to the user
   * @param forgotPasswordDto - The forgot password DTO containing the user's email
   * @param origin - The origin URL of the application
   * @returns The message info of the email sent
   * @throws NotFoundException if the email is not found
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto, origin: string) {
    const data = await this.userService.findOne({
      email: forgotPasswordDto.email,
    });

    if (!data) {
      throw new NotFoundException('Enter a valid email');
    }

    const createToken = await this.authRepository.getRefreshToken(
      forgotPasswordDto.email,
    );

    const message = `You link is ${origin}/reset-password?token=${createToken}`;

    const messageInfo = await this.emailService.sendEmail(
      forgotPasswordDto.email,
      'Reset Password Link',
      message,
    );

    return messageInfo;
  }

  /**
   * Reset the password of a user
   * @param resetPasswordDto - The reset password DTO containing the user's email, new password, and token
   * @returns The updated user object
   * @throws BadRequestException if the email or token is invalid
   */
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

  /**
   * Sign out a user
   * @param id - The ID of the user
   * @returns Promise that resolves when the user is signed out
   */
  async signOut(id: string) {
    return this.authRepository.updateRefreshTokenInUser(null, id);
  }

  /**
   * Get a user based on the given condition
   * @param condition - The condition to find the user
   * @returns The user object that matches the condition
   */
  async getUser(condition: object) {
    return await this.userService.findOne(condition);
  }
}
