import { MiddlewareConsumer, Module, NestModule, RequestMethod, OnModuleInit, Logger } from "@nestjs/common"
import { MongooseModule, InjectConnection } from "@nestjs/mongoose"
import { AuthModule } from "@/modules/auth/auth.module"
import { UserModule } from "@/modules/user/user.module"
import { HealthCheckModule } from "@/modules/health-check/health-check.module"
import { EmailModule } from "@/modules/email/email.module"
import { RedisModule } from "@/modules/redis/redis.module"
import { RateLimitMiddleware } from "@/middleware/rate-limit.middleware"
import { SecurityHeadersMiddleware } from "@/middleware/security-headers.middleware"
import { RolesGuard } from "@/guards/roles.guard"
import config from "@/config"
import { Connection } from "mongoose"
import { APP_GUARD } from "@nestjs/core"
import { Reflector } from "@nestjs/core"

@Module({
  imports: [
    MongooseModule.forRoot(config.MONGO.URL, {
      dbName: config.MONGO.DB_NAME
    }),
    RedisModule,
    AuthModule,
    UserModule,
    HealthCheckModule,
    EmailModule
  ],
  providers: [
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    Reflector,
    {
      provide: APP_GUARD,
      useClass: RolesGuard
    }
  ]
})
export class AppModule implements NestModule, OnModuleInit {
  private readonly logger = new Logger(AppModule.name)

  constructor(@InjectConnection() private readonly dbConnection: Connection) {}

  async onModuleInit() {
    // 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
    if (this.dbConnection.readyState === 1) {
      this.logger.log("MongoDB connected successfully (readyState = 1)")
    } else {
      // Listen for future connection
      this.dbConnection.once("connected", () => {
        this.logger.log("MongoDB connected successfully")
      })
    }

    this.dbConnection.on("error", (err) => {
      this.logger.error(`MongoDB connection error: ${err.message}`)
    })
  }

  configure(consumer: MiddlewareConsumer) {
    // Apply security headers to all routes
    consumer.apply(SecurityHeadersMiddleware).forRoutes({ path: "*path", method: RequestMethod.ALL })

    // Apply rate limiting to all routes (more granular limits defined in middleware)
    consumer.apply(RateLimitMiddleware).forRoutes({ path: "*path", method: RequestMethod.ALL })
  }
}
