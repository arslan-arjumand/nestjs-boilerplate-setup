import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
// @Controller
import { AuthController } from './auth.controller';
// @Services
import { AuthService } from './service/auth.service';
// @JWT Strategy

import { LocalStrategy } from './jwt/local.strategy';
// @Configuration
import configuration from 'config/index';
// @Modules
import { UserModule } from '../user/user.module';
// @Repository
import { AuthRepository } from './repository/auth.repository';
import { EmailModule } from '../email/email.module';

const { JWT_SECRET_TOKEN, JWT_TOKEN_EXPIRATION } = configuration().JWT;

@Module({
  imports: [
    // Passport
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
