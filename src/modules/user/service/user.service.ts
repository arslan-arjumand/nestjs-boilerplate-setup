import { Injectable } from "@nestjs/common"
import { UserRepository } from "../repository/user.repository"
import { EntityServices } from "@/modules/common/entity.service"
import { Users } from "../schema/user.schema"
import { CreateUserDto } from "../dto/create-user.dto"
import { UpdateUserDto } from "../dto/update-user.dto"

/**
 * Service responsible for handling user-related operations.
 */
@Injectable()
export class UserService extends EntityServices {
  /**
   * Creates an instance of UserService.
   * @param userRepository The user repository used for database operations.
   */
  constructor(private readonly userRepository: UserRepository) {
    super(userRepository)
  }

  /**
   * Creates a new user.
   * @param createUserDto The DTO for creating the user.
   * @returns The created user.
   */
  async create(createUserDto: CreateUserDto | any): Promise<Users> {
    return this.userRepository.create(createUserDto)
  }

  /**
   * Updates a user.
   * @param condition The condition for finding the user.
   * @param updateUserDto The DTO for updating the user.
   * @returns The updated user.
   */
  async update(condition: object, updateUserDto: UpdateUserDto | any): Promise<Users | null> {
    return this.userRepository.findOneAndUpdate(condition, updateUserDto)
  }
}
