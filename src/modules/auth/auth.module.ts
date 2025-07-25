import { Module } from "@nestjs/common"
import { JwtModule } from "@nestjs/jwt"
import { PassportModule } from "@nestjs/passport"
import { MongooseModule } from "@nestjs/mongoose"
import { AuthController } from "@/modules/auth/auth.controller"
import { SecurityEventController } from "@/modules/auth/security-event.controller"
import { UserSessionController } from "@/modules/auth/user-session.controller"
import { AuthService } from "@/modules/auth/service/auth.service"
import { SecurityEventService } from "@/modules/auth/service/security-event.service"
import { UserSessionService } from "@/modules/auth/service/user-session.service"
import { RedisTokenBlacklistService } from "@/modules/auth/service/redis-token-blacklist.service"
import { SecurityLoggerService } from "@/modules/auth/service/security-logger.service"
import { SessionManagerService } from "@/modules/auth/service/session-manager.service"
import { LocalStrategy } from "@/modules/auth/jwt/local.strategy"
import { UserModule } from "@/modules/user/user.module"
import { AuthRepository } from "@/modules/auth/repository/auth.repository"
import { SecurityEventRepository } from "@/modules/auth/repository/security-event.repository"
import { UserSessionRepository } from "@/modules/auth/repository/user-session.repository"
import { EmailModule } from "@/modules/email/email.module"
import { RedisModule } from "@/modules/redis/redis.module"

// Import schemas
import { SecurityEvent, SecurityEventSchema } from "@/modules/auth/schema/security-event.schema"
import { UserSession, UserSessionSchema } from "@/modules/auth/schema/user-session.schema"

import config from "@/config"

const { JWT_SECRET_TOKEN, JWT_SECRET_TOKEN_EXPIRATION, JWT_REFRESH_TOKEN } = config.JWT

/**
 * The `AuthModule` is responsible for handling authentication-related functionality.
 * It imports necessary modules, registers controllers, and provides services and strategies.
 * Now includes persistent security event logging and session management.
 */
@Module({
  imports: [
    PassportModule.register({}),
    JwtModule.register({
      privateKey: Buffer.from(JWT_SECRET_TOKEN, "base64").toString("utf8"),
      publicKey: Buffer.from(JWT_REFRESH_TOKEN, "base64").toString("utf8"),
      signOptions: {
        expiresIn: JWT_SECRET_TOKEN_EXPIRATION,
        algorithm: "RS256"
      }
    }),
    // MongoDB schemas for persistent data
    MongooseModule.forFeature([
      { name: SecurityEvent.name, schema: SecurityEventSchema },
      { name: UserSession.name, schema: UserSessionSchema }
    ]),
    UserModule,
    EmailModule,
    RedisModule
  ],
  controllers: [AuthController, SecurityEventController, UserSessionController],
  providers: [
    AuthService,
    SecurityEventService,
    UserSessionService,
    AuthRepository,
    SecurityEventRepository,
    UserSessionRepository,
    RedisTokenBlacklistService,
    SecurityLoggerService,
    SessionManagerService,
    LocalStrategy
  ],
  exports: [
    AuthService,
    SecurityEventService,
    UserSessionService,
    AuthRepository,
    SecurityEventRepository,
    UserSessionRepository,
    RedisTokenBlacklistService,
    SecurityLoggerService,
    SessionManagerService
  ]
})
export class AuthModule {}
