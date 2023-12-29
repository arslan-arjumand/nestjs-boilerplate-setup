import { ApiProperty } from "@nestjs/swagger";
import { IsString } from "class-validator";

export class ForgotPasswordDto {
  @ApiProperty()
  @IsString({ message: 'Email must be a string' })
  readonly email: string;
}
