import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, IsOptional } from 'class-validator';
import { Document, FilterQuery } from 'mongoose';

export type IEntity = Document;

export interface IFindQuery {
  filterQuery?: any;
  projection?: Record<string, unknown>;
  page?: number;
  limit?: number;
  populate?: any;
  sort?: any;
  select?: any;
}

export class QueryDto {
  @ApiProperty({
    minimum: 0,
    maximum: 10000,
    title: 'Page',
    exclusiveMaximum: true,
    exclusiveMinimum: true,
    format: 'int32',
    default: 0,
  })
  @IsNumber()
  @IsOptional()
  public page = 1;

  @ApiProperty()
  @IsNumber()
  @IsOptional()
  public limit = 25;
}
