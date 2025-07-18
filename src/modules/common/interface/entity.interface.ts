import { ApiProperty } from "@nestjs/swagger"
import { IsNumber, IsOptional } from "class-validator"
import { Document } from "mongoose"

export type IEntity = Document

/**
 * Represents a query object used for finding entities.
 */
export interface IFindQuery {
  /**
   * Specifies the filter query to apply when finding entities.
   */
  filterQuery?: any

  /**
   * Specifies the projection fields to include or exclude when finding entities.
   */
  projection?: Record<string, unknown>

  /**
   * Specifies the page number for pagination when finding entities.
   */
  page?: number

  /**
   * Specifies the maximum number of entities to return per page when paginating.
   */
  limit?: number

  /**
   * Specifies the fields to populate when finding entities.
   */
  populate?: any

  /**
   * Specifies the sorting criteria when finding entities.
   */
  sort?: any

  /**
   * Specifies the fields to select when finding entities.
   */
  select?: any
}

/**
 * Represents a query DTO (Data Transfer Object) used for pagination.
 */
export class QueryDto {
  /**
   * The page number for pagination. Defaults to 1 if not provided.
   *
   * @minimum 0
   * @maximum 10000
   * @title Page
   * @exclusiveMaximum true
   * @exclusiveMinimum true
   * @format int32
   * @default 0
   */
  @ApiProperty({
    minimum: 0,
    maximum: 10000,
    title: "Page",
    exclusiveMaximum: true,
    exclusiveMinimum: true,
    format: "int32",
    default: 0
  })
  @IsNumber()
  @IsOptional()
  public page = 1

  /**
   * The maximum number of items to return per page. Defaults to 25 if not provided.
   */
  @ApiProperty()
  @IsNumber()
  @IsOptional()
  public limit = 25
}
