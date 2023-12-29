import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length } from 'class-validator';

export class VerifyEmailToken {
  @ApiProperty()
  @IsString()
  token: string;

  @ApiProperty()
  @IsString()
  email: string;
}
