import { ApiProperty } from "@nestjs/swagger"
import { IsString, IsOptional, MinLength, IsEnum } from "class-validator"
import { UserRole } from "@/enums"

/**
 * Data transfer object for updating a user.
 */
export class UpdateUserDto {
  /**
   * The username of the user.
   */
  @ApiProperty({ required: false })
  @IsString({ message: "Username must be a string" })
  @IsOptional()
  readonly username?: string

  /**
   * The email address of the user.
   */
  @ApiProperty({ required: false })
  @IsString({ message: "Email must be a string" })
  @IsOptional()
  readonly email?: string

  /**
   * The avatar URL of the user.
   */
  @ApiProperty({ required: false })
  @IsString({ message: "Avatar must be a string" })
  @IsOptional()
  readonly avatar?: string

  /**
   * The role of the user.
   * This field is optional.
   */
  @ApiProperty({ enum: UserRole, required: false })
  @IsEnum(UserRole, { message: "Role must be either USER or ADMIN" })
  @IsOptional()
  readonly role?: UserRole
}

/**
 * Data transfer object for updating a user's password.
 */
export class UpdatePasswordDto {
  /**
   * The current password of the user.
   */
  @ApiProperty()
  @IsString({ message: "Current password must be a string" })
  readonly currentPassword: string

  /**
   * The new password of the user.
   */
  @ApiProperty()
  @IsString({ message: "New password must be a string" })
  @MinLength(8, { message: "New password must be at least 8 characters long" })
  readonly newPassword: string
}
