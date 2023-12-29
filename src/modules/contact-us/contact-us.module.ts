import { MongooseModule } from '@nestjs/mongoose';
import { Module } from '@nestjs/common';
// @Controller
import { ContactUsController } from './contact-us.controller';
// @Services
import { ContactUsService } from './service/contact-us.service';
// @Repositories
import { ContactUsRepository } from './repository/contact-us.repository';
// @Schema
import { ContactUs, ContactUsSchema } from './schema/contact-us.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: ContactUs.name, schema: ContactUsSchema },
    ]),
  ],
  controllers: [ContactUsController],
  providers: [ContactUsService, ContactUsRepository],
})
export class ContactUsModule {}
