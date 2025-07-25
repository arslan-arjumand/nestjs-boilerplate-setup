import { MongooseModule } from "@nestjs/mongoose"
import { Module } from "@nestjs/common"
import { UserController } from "@/modules/user/user.controller"
import { UserService } from "@/modules/user/service/user.service"
import { UserRepository } from "@/modules/user/repository/user.repository"
import { Users, UsersSchema } from "@/modules/user/schema/user.schema"

/**
 * Represents the user module of the application.
 * This module is responsible for handling user-related operations.
 */
@Module({
  imports: [MongooseModule.forFeature([{ name: Users.name, schema: UsersSchema }])],
  controllers: [UserController],
  providers: [UserService, UserRepository],
  exports: [UserService]
})
export class UserModule {}
