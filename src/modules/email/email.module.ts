import { Module } from "@nestjs/common"
import { EmailService } from "@/modules/email/email.service"

/**
 * The EmailModule is responsible for providing the EmailService to other modules.
 */
@Module({
  providers: [EmailService],
  exports: [EmailService]
})
export class EmailModule {}
