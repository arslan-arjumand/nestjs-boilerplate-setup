import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length } from 'class-validator';

/**
 * Data transfer object for resetting password.
 */
export class ResetPasswordDto {
  /**
   * The reset token received by the user.
   */
  @ApiProperty()
  @IsString()
  token: string;

  /**
   * The email address of the user.
   */
  @ApiProperty()
  @IsString()
  email: string;

  /**
   * The new password for the user.
   * Password must be at least 8 characters long.
   */
  @ApiProperty({
    minimum: 8,
    maximum: 150,
    description: 'Password Length must be at least 8 characters',
  })
  @IsString()
  @Length(8, 150, { message: 'Password Length must be at least 8 characters' })
  password: string;
}
