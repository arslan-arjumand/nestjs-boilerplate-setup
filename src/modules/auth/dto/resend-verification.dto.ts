import { ApiProperty } from "@nestjs/swagger"
import { IsEmail, IsNotEmpty } from "class-validator"

/**
 * Data transfer object for resending email verification.
 */
export class ResendVerificationDto {
  /**
   * The email address to resend verification to.
   *
   * @example john@example.com
   */
  @ApiProperty({
    description: "Email address to resend verification to",
    example: "john@example.com"
  })
  @IsEmail({}, { message: "Please provide a valid email address" })
  @IsNotEmpty()
  email: string
}
