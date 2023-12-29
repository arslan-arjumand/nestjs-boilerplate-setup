import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsOptional, Matches } from 'class-validator';

export class CreateUserDto {
  @ApiProperty()
  @IsString({ message: 'Username must be a string' })
  readonly username: string;

  @ApiProperty()
  @IsString({ message: 'Email must be a string' })
  readonly email: string;

  @ApiProperty()
  @IsString({ message: 'Password must be a string' })
  @IsOptional()
  readonly password: string;

  @ApiProperty()
  @IsString({ message: 'Phone number must be a string' })
  @IsOptional()
  // @Matches(/^((\+92)?(0092)?(92)?(0)?)(3)([0-9]{9})$/, {
  //   message: 'Enter a valid phone number',
  // })
  readonly phone_number: string;

  @ApiProperty()
  @IsOptional()
  @IsString({ message: 'Avatar must be a string' })
  readonly avatar: string;
}

export class CheckUserDto {
  @ApiProperty()
  @IsString({ message: 'Email must be a string' })
  readonly email: string;
}
