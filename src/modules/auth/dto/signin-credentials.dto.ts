import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsString, Length } from 'class-validator';

export class SignInCredentialsDto {
  @ApiProperty()
  @IsString()
  email: string;

  @ApiProperty({
    minimum: 8,
    description: 'Password Length must be at least 8 characters',
  })
  @IsString()
  @Length(8, 150, { message: 'Password Length must be at least 8 characters' })
  password: string;
}

export class GoogleSignInCredentialsDto {
  @ApiProperty()
  @IsString()
  email: string;

  @ApiProperty()
  @IsString()
  username: string;

  @ApiProperty()
  @IsString()
  avatar: string;

  @ApiProperty()
  @IsBoolean()
  isVerified: boolean;

  @ApiProperty()
  @IsString()
  googleId: string;
}
