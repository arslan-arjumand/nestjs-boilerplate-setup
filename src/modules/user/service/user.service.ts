import { Injectable, Logger } from "@nestjs/common"
import { UserRepository } from "@/modules/user/repository/user.repository"
import { EntityServices } from "@/modules/common/entity.service"
import { Users } from "@/modules/user/schema/user.schema"
import { CreateUserDto } from "@/modules/user/dto/create-user.dto"
import { UpdateUserDto } from "@/modules/user/dto/update-user.dto"

/**
 * Service responsible for handling user-related operations.
 */
@Injectable()
export class UserService extends EntityServices {
  private readonly logger = new Logger(UserService.name)

  /**
   * Creates an instance of UserService.
   * @param userRepository The user repository used for database operations.
   */
  constructor(private readonly userRepository: UserRepository) {
    super(userRepository)
    this.logger.log("User service initialized successfully")
  }

  /**
   * Creates a new user.
   * @param createUserDto The DTO for creating the user.
   * @returns The created user.
   */
  async create(createUserDto: CreateUserDto | any): Promise<Users> {
    try {
      this.logger.log(`Creating new user with email: ${createUserDto.email}`)
      const user = await this.userRepository.create(createUserDto)
      this.logger.log(`User created successfully with ID: ${user.id}`)
      return user
    } catch (error) {
      this.logger.error(`Failed to create user with email ${createUserDto.email}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Updates a user.
   * @param condition The condition for finding the user.
   * @param updateUserDto The DTO for updating the user.
   * @returns The updated user.
   */
  async update(condition: object, updateUserDto: UpdateUserDto | any): Promise<Users | null> {
    try {
      this.logger.log(`Updating user with condition: ${JSON.stringify(condition)}`)
      const user = await this.userRepository.findOneAndUpdate(condition, updateUserDto)
      if (user) {
        this.logger.log(`User updated successfully with ID: ${user.id}`)
      } else {
        this.logger.warn(`No user found to update with condition: ${JSON.stringify(condition)}`)
      }
      return user
    } catch (error) {
      this.logger.error(`Failed to update user: ${error.message}`, error.stack)
      throw error
    }
  }
}
