import {
  Controller,
  Get,
  UseInterceptors,
  ClassSerializerInterceptor,
  Res,
  HttpStatus,
  HttpException
} from "@nestjs/common"
import { ApiTags } from "@nestjs/swagger"
import { Response } from "express"

@ApiTags("Heatlh-Check")
@Controller("health-check")
export class HealthCheckController {
  constructor() {}

  /**
   * @description health check
   * @method Get
   * @param response
   * @return health check message
   */
  @UseInterceptors(ClassSerializerInterceptor)
  @Get()
  async healthCheck(@Res() response: Response) {
    try {
      response.status(HttpStatus.OK).json({
        status: HttpStatus.OK,
        message: "Health check is successful"
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }
}
