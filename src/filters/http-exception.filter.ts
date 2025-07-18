import { HttpAdapterHost } from "@nestjs/core"
import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from "@nestjs/common"
import config from "@/config"

/**
 * Custom exception filter for handling HTTP exceptions.
 */
@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger: Logger

  /**
   * Creates an instance of HttpExceptionFilter.
   * @param httpAdapterHost - The HttpAdapterHost instance.
   */
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {
    this.logger = new Logger()
  }

  /**
   * Handles the exception and sends an appropriate response.
   * @param exception - The exception object.
   * @param host - The ArgumentsHost object.
   */
  catch(exception: HttpException, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const request = ctx.getRequest()

    const status =
      (exception instanceof HttpException && exception.getStatus()) ||
      exception["status"] ||
      HttpStatus.INTERNAL_SERVER_ERROR

    const message =
      (exception instanceof HttpException && exception.getResponse()?.["message"]) ||
      exception["message"] ||
      "Internal server error"

    // @Error format for development ENV
    const devErrorResponse = {
      timestamp: new Date().toISOString(),
      message,
      status,
      data: {
        path: request.url,
        method: request.method
      }
    }
    // @Error format for production ENV
    const prodErrorResponse = {
      statusCode: status,
      message
    }

    // Send Error
    httpAdapter.reply(
      ctx.getResponse(),
      config.SERVER.ENVIRONMENT === "development" ? devErrorResponse : prodErrorResponse,
      status
    )

    // send log
    this.logger.log(config.SERVER.ENVIRONMENT === "development" ? devErrorResponse : prodErrorResponse)
  }
}
