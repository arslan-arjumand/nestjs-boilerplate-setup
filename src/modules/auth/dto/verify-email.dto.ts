import { ApiProperty } from "@nestjs/swagger"
import { IsString, IsNotEmpty } from "class-validator"

/**
 * Data transfer object for email verification.
 */
export class VerifyEmailDto {
  /**
   * The email verification token sent to user's email.
   *
   * @example abc123def456ghi789
   */
  @ApiProperty({
    description: "Email verification token",
    example: "abc123def456ghi789"
  })
  @IsString()
  @IsNotEmpty()
  token: string
}
