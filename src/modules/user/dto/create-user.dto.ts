import { ApiProperty } from "@nestjs/swagger"
import { IsString, IsOptional } from "class-validator"

/**
 * Data transfer object for create user functionality.
 */
export class CreateUserDto {
  /**
   * The username of the user.
   */
  @ApiProperty()
  @IsString({ message: "Username must be a string" })
  readonly username: string

  /**
   * The email address of the user.
   */
  @ApiProperty()
  @IsString({ message: "Email must be a string" })
  readonly email: string

  /**
   * The password of the user.
   * This field is optional.
   */
  @ApiProperty()
  @IsString({ message: "Password must be a string" })
  @IsOptional()
  readonly password: string
}
