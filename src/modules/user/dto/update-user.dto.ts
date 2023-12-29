import { ApiProperty, PartialType } from '@nestjs/swagger';
import { IsOptional, IsString, Length } from 'class-validator';
// @Dto
import { CreateUserDto } from './create-user.dto';

export class UpdateUserDto extends PartialType(CreateUserDto) {}

// Update User Password
export class UpdatePasswordDto {
  @ApiProperty()
  @IsString()
  @IsOptional()
  currentPassword: string;

  @ApiProperty()
  @IsString()
  @IsOptional()
  newPassword: string;
}
