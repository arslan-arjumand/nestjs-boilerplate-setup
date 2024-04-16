import { MongooseModule } from '@nestjs/mongoose';
import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './service/user.service';
import { UserRepository } from './repository/user.repository';
import { Users, UsersSchema } from './schema/user.schema';

/**
 * Represents the user module of the application.
 * This module is responsible for handling user-related operations.
 */
@Module({
  imports: [
    MongooseModule.forFeature([{ name: Users.name, schema: UsersSchema }]),
  ],
  controllers: [UserController],
  providers: [UserService, UserRepository],
  exports: [UserService],
})
export class UserModule {}
