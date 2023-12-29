import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, Length, Matches } from 'class-validator';

export class SignupCredentialsDto {
  @ApiProperty()
  @IsString()
  username: string;

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

  @ApiProperty({ minimum: 7, maximum: 15 })
  @IsString()
  // @Matches(/^((\+92)?(0092)?(92)?(0)?)(3)([0-9]{9})$/, {
  //   message: 'Enter a valid phone number',
  // })
  phone_number: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  avatar: string;
}
