import { Module } from "@nestjs/common"
import { ThrottlerModule } from "@nestjs/throttler"
import { MongooseModule } from "@nestjs/mongoose"
import config from "@/config"

// Modules
import { HealthCheckModule } from "./modules/health-check/health-check.module"
import { AuthModule } from "./modules/auth/auth.module"
import { UserModule } from "./modules/user/user.module"
import { EmailModule } from "./modules/email/email.module"

// App Module
@Module({
  imports: [
    ThrottlerModule.forRoot([]),
    MongooseModule.forRoot(config.MONGO.URL, {
      dbName: config.MONGO.DB_NAME,
      autoIndex: true
    }),
    HealthCheckModule,
    AuthModule,
    UserModule,
    EmailModule
  ]
})
export class AppModule {}
