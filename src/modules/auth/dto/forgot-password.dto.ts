import { ApiProperty } from "@nestjs/swagger";
import { IsString } from "class-validator";

/**
 * Data transfer object for forgot password functionality.
 */
export class ForgotPasswordDto {
  /**
   * The email address of the user.
   * 
   * @example john@example.com
   */
  @ApiProperty()
  @IsString({ message: 'Email must be a string' })
  readonly email: string;
}
