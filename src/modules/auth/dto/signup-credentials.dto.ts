import { ApiProperty } from "@nestjs/swagger"
import { IsOptional, IsString, Length, IsEmail } from "class-validator"

/**
 * Data transfer object for signup credentials.
 */
export class SignupCredentialsDto {
  /**
   * The username of the user.
   *
   * @example john_doe
   */
  @ApiProperty()
  @IsString()
  username: string

  /**
   * The email address of the user.
   *
   * @example john@example.com
   */
  @ApiProperty()
  @IsEmail({}, { message: "Please provide a valid email address" })
  email: string

  /**
   * The password of the user.
   *
   * @example P@ssw0rd
   * @minimum 8
   * @description Password Length must be at least 8 characters.
   */
  @ApiProperty({
    minimum: 8,
    description: "Password Length must be at least 8 characters"
  })
  @IsString()
  @Length(8, 150, { message: "Password Length must be at least 8 characters" })
  password: string
}
