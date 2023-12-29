import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
// @Schema
import { ContactUs, ContactUsDocument } from '../schema/contact-us.schema';
// @Repositories
import { EntityRepository } from 'src/modules/common/repository/entity.repository';

@Injectable()
export class ContactUsRepository extends EntityRepository<ContactUs> {
  constructor(
    @InjectModel(ContactUs.name) classModel: Model<ContactUsDocument>,
  ) {
    super(classModel);
  }
}
