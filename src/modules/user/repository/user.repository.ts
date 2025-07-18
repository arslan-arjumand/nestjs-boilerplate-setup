import { Injectable } from "@nestjs/common"
import { InjectModel } from "@nestjs/mongoose"
import { Model } from "mongoose"
import { EntityRepository } from "@/modules/common/repository/entity.repository"
import { Users, UsersDocument } from "../schema/user.schema"

/**
 * Repository for managing User entities.
 */
@Injectable()
export class UserRepository extends EntityRepository<UsersDocument> {
  /**
   * Creates an instance of UserRepository.
   * @param userModel The injected Mongoose model for the User entity.
   */
  constructor(@InjectModel(Users.name) userModel: Model<UsersDocument>) {
    super(userModel)
  }
}
