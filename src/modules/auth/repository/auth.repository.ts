/**
 * Repository class for handling authentication-related operations.
 */
import {
  HttpException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/modules/user/service/user.service';
import Configuration from 'config/index';

const {
  JWT_SECRET_TOKEN,
  JWT_SECRET_REFRESH_TOKEN,
  JWT_TOKEN_EXPIRATION,
  JWT_REFRESH_TOKEN_EXPIRATION,
} = Configuration().JWT;

@Injectable()
export class AuthRepository {
  constructor(
    private readonly userServices: UserService,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * Updates the refresh token for a user.
   * @param refreshToken - The new refresh token.
   * @param id - The ID of the user.
   * @returns A promise that resolves to the updated user.
   */
  async updateRefreshTokenInUser(refreshToken: string, id: string) {
    if (refreshToken) {
      refreshToken = await bcrypt.hash(refreshToken, 10);
    }

    return this.userServices.update(
      { _id: id },
      {
        refresh_token: refreshToken,
      },
    );
  }

  /**
   * Generates an access token for a user.
   * @param id - The ID of the user.
   * @param expiresIn - The expiration time for the token (optional).
   * @returns A promise that resolves to the access token.
   */
  async getAccessToken(id: string, expiresIn?: string) {
    return this.jwtService.sign(
      { _id: id },
      {
        secret: JWT_SECRET_TOKEN,
        expiresIn: expiresIn || JWT_TOKEN_EXPIRATION,
      },
    );
  }

  /**
   * Generates a refresh token for a user.
   * @param id - The ID of the user.
   * @param expiresIn - The expiration time for the token (optional).
   * @returns A promise that resolves to the refresh token.
   */
  async getRefreshToken(id: string, expiresIn?: string) {
    return this.jwtService.sign(
      { _id: id },
      {
        secret: JWT_SECRET_REFRESH_TOKEN,
        expiresIn: expiresIn || JWT_REFRESH_TOKEN_EXPIRATION,
      },
    );
  }

  /**
   * Verifies the validity of a token.
   * @param token - The token to verify.
   * @returns The user associated with the token.
   * @throws UnauthorizedException if the token is invalid or expired.
   */
  async verifyToken(token: string) {
    this.jwtService.verify(token, {
      secret: JWT_SECRET_TOKEN,
    });

    const decodeToken: any = this.jwtService.decode(token, {
      json: true,
    });

    if (!decodeToken) {
      throw new UnauthorizedException();
    }

    // Find user
    const user = await this.userServices.findOne({
      email: decodeToken._id,
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }

  /**
   * Retrieves the user associated with a refresh token.
   * @param refreshToken - The refresh token.
   * @returns A promise that resolves to the user.
   * @throws NotFoundException if the user is not found.
   * @throws HttpException if an error occurs during the operation.
   */
  async getUserIfRefreshTokenMatches(refreshToken: string) {
    try {
      const user = await this.userServices.findOne({
        refresh_token: refreshToken,
      });
      if (!user) {
        throw new NotFoundException('Enter a valid address ID');
      }

      await this.updateRefreshTokenInUser(null, user.id);
      return user;
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  /**
   * Generates a new access token and refresh token for a user.
   * @param id - The ID of the user.
   * @returns A promise that resolves to an object containing the new access token and refresh token.
   */
  async getNewAccessAndRefreshToken(id: string) {
    const refreshToken = await this.getRefreshToken(id);
    await this.updateRefreshTokenInUser(refreshToken, id);

    return {
      accessToken: await this.getAccessToken(id),
      refreshToken: refreshToken,
    };
  }
}
