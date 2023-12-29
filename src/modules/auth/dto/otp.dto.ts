import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class CreateOtpDto {
  @ApiProperty()
  @IsString()
  email: string;
}

export class VerifyOtpDto {
  @ApiProperty()
  @IsString()
  email: string;

  @ApiProperty()
  @IsString()
  otp: string;
}
