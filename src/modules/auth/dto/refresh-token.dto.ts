import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

/**
 * Data transfer object for refreshing a token.
 */
export class RefreshTokenDto {
  /**
   * The refresh token.
   */
  @ApiProperty()
  @IsString()
  refresh_token: string;
}
