import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class CreateContactUsDto {
  @ApiProperty()
  @IsString({ message: 'Name must be a string' })
  readonly name: string;

  @ApiProperty()
  @IsString({ message: 'Email must be a string' })
  readonly email: string;

  @ApiProperty()
  @IsString({ message: 'Message must be a string' })
  readonly message: string;
}
