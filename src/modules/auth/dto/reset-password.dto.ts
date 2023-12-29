import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty()
  @IsString()
  token: string;

  @ApiProperty()
  @IsString()
  email: string;

  @ApiProperty({
    minimum: 8,
    maximum: 150,
    description: 'Password Length must be at least 8 characters',
  })
  @IsString()
  @Length(8, 150, { message: 'Password Length must be at least 8 characters' })
  password: string;
}
