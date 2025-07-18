import { ApiProperty, PartialType } from "@nestjs/swagger"
import { IsOptional, IsString, Length } from "class-validator"
import { CreateUserDto } from "./create-user.dto"

/**
 * Data transfer object for updating a user.
 * Extends the `CreateUserDto` class.
 */
export class UpdateUserDto extends PartialType(CreateUserDto) {}

/**
 * Data transfer object for updating a user's password.
 */
export class UpdatePasswordDto {
  /**
   * The current password of the user.
   */
  @ApiProperty()
  @IsString()
  @IsOptional()
  currentPassword: string

  /**
   * The new password for the user.
   */
  @ApiProperty()
  @IsString()
  @IsOptional()
  newPassword: string
}
