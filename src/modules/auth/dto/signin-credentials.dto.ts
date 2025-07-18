import { ApiProperty } from "@nestjs/swagger"
import { IsString, Length } from "class-validator"

/**
 * Data transfer object for signin credentials.
 */
export class SignInCredentialsDto {
  /**
   * Email of the user.
   */
  @ApiProperty()
  @IsString()
  email: string

  /**
   * Password of the user.
   * Must be at least 8 characters long.
   */
  @ApiProperty({
    minimum: 8,
    description: "Password Length must be at least 8 characters"
  })
  @IsString()
  @Length(8, 150, { message: "Password Length must be at least 8 characters" })
  password: string
}
