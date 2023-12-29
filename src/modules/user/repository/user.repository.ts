import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
// @Schema
import { Users, UsersDocument } from '../schema/user.schema';
// @Repositories
import { EntityRepository } from 'src/modules/common/repository/entity.repository';

@Injectable()
export class UserRepository extends EntityRepository<UsersDocument> {
  constructor(@InjectModel(Users.name) userModel: Model<UsersDocument>) {
    super(userModel);
  }
}
