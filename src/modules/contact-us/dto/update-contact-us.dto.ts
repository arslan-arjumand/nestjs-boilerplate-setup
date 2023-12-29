import { PartialType } from '@nestjs/swagger';
// @Dto
import { CreateContactUsDto } from './create-contact-us.dto';

export class UpdateContactUsDto extends PartialType(CreateContactUsDto) {}
