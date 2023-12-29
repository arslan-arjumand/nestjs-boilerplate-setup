import { Injectable } from '@nestjs/common';
// @Repositories
import { ContactUsRepository } from '../repository/contact-us.repository';
// @Services
import { EntityServices } from 'src/modules/common/entity.service';

@Injectable()
export class ContactUsService extends EntityServices {
  constructor(private readonly contactUsRepository: ContactUsRepository) {
    super(contactUsRepository);
  }
}
