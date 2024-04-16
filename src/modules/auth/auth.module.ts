import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './service/auth.service';
import { LocalStrategy } from './jwt/local.strategy';
import configuration from 'config/index';
import { UserModule } from '../user/user.module';
import { AuthRepository } from './repository/auth.repository';
import { EmailModule } from '../email/email.module';

const { JWT_SECRET_TOKEN, JWT_TOKEN_EXPIRATION } = configuration().JWT;

/**
 * The `AuthModule` is responsible for handling authentication-related functionality.
 * It imports necessary modules, registers controllers, and provides services and strategies.
 */
@Module({
  imports: [
    PassportModule.register({}),
    JwtModule.register({
      secret: JWT_SECRET_TOKEN,
      signOptions: {
        expiresIn: JWT_TOKEN_EXPIRATION,
      },
    }),
    UserModule,
    EmailModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, AuthRepository, LocalStrategy],
})
export class AuthModule {}
