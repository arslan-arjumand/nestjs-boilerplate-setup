import { Injectable } from '@nestjs/common';
import { UserRepository } from '../repository/user.repository';
import { EntityServices } from 'src/modules/common/entity.service';

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
    super(userRepository);
  }
}
