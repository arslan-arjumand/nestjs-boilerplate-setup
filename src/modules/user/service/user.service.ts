import { Injectable } from '@nestjs/common';
// @Repositories
import { UserRepository } from '../repository/user.repository';
// @Services
import { EntityServices } from 'src/modules/common/entity.service';

@Injectable()
export class UserService extends EntityServices {
  constructor(private readonly userRepository: UserRepository) {
    super(userRepository);
  }
}
