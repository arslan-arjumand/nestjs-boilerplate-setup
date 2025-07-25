import {
  Controller,
  Get,
  UseInterceptors,
  ClassSerializerInterceptor,
  Res,
  HttpStatus,
  HttpException
} from "@nestjs/common"
import { ApiTags, ApiOperation, ApiResponse } from "@nestjs/swagger"
import { Response } from "express"
import { generalResponse } from "@/utils"

@ApiTags("Health-Check")
@Controller("health-check")
export class HealthCheckController {
  constructor() {}

  /**
   * Health Check Endpoint
   *
   * GET /health-check
   * Purpose: Check if the API is running and healthy
   * Function: Returns a success response indicating the API is operational
   * Auth Required: No
   * Description: Simple endpoint to verify API availability and health status
   *
   * @method GET
   * @param response - Express response object
   * @returns Health check status message
   */
  @Get()
  @UseInterceptors(ClassSerializerInterceptor)
  @ApiOperation({
    summary: "API Health Check",
    description: "Check if the API is running and healthy"
  })
  @ApiResponse({
    status: 200,
    description: "API is healthy and operational",
    schema: {
      example: {
        status: 200,
        message: "Health check is successful",
        data: null
      }
    }
  })
  async healthCheck(@Res() response: Response) {
    try {
      generalResponse({
        response,
        message: "Health check is successful",
        status: HttpStatus.OK,
        data: null
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }
}
