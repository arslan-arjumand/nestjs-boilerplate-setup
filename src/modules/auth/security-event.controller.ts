import {
  Body,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Post,
  Patch,
  Delete,
  Res,
  UseGuards,
  UseInterceptors,
  ClassSerializerInterceptor,
  Query,
  NotFoundException
} from "@nestjs/common"
import { AuthGuard } from "@nestjs/passport"
import { Response } from "express"
import { ApiBearerAuth, ApiTags, ApiOperation } from "@nestjs/swagger"
import { SecurityEventService } from "./service/security-event.service"
import { QueryDto } from "@/modules/common/interface/entity.interface"
import { generalResponse } from "@/utils"
import { Roles } from "@/decorators"
import { UserRole } from "@/enums"

@ApiTags("Security Events")
@ApiBearerAuth()
@UseGuards(AuthGuard("validate_token"))
@Roles(UserRole.ADMIN)
@UseInterceptors(ClassSerializerInterceptor)
@Controller("security-events")
export class SecurityEventController {
  constructor(private readonly securityEventService: SecurityEventService) {}

  /**
   * Get all security events with pagination
   *
   * GET /security-events
   * Purpose: Get all security events with pagination support
   * Function: Retrieves paginated list of all security events from database
   * Auth Required: Yes (Bearer token)
   * Description: Admin endpoint to view all security events with pagination
   *
   * @method GET
   * @param query - Pagination query parameters
   * @param response - Express response object
   * @returns Paginated list of security events
   */
  @Get()
  @ApiOperation({
    summary: "Get all security events with pagination",
    description: "Retrieve all security events with pagination support"
  })
  async findAllPaginated(@Res() response: Response, @Query() query: QueryDto) {
    try {
      const data = await this.securityEventService.findAllWithPagination({
        page: query.page || 1,
        limit: query.limit || 25
      })

      generalResponse({
        response,
        message: "Security events retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get security event by ID
   *
   * GET /security-events/:id
   * Purpose: Get a specific security event by ID
   * Function: Retrieves complete security event data from database
   * Auth Required: Yes (Bearer token)
   * Description: Retrieve detailed information about a specific security event
   *
   * @method GET
   * @param id - Security event ID
   * @param response - Express response object
   * @returns Security event document
   */
  @Get(":id")
  @ApiOperation({
    summary: "Get security event by ID",
    description: "Retrieve a specific security event by its ID"
  })
  async findOne(@Param("id") id: string, @Res() response: Response) {
    try {
      const data = await this.securityEventService.findOne({ _id: id })
      if (!data) {
        throw new NotFoundException("Security event not found")
      }

      generalResponse({
        response,
        message: "Security event retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get security events by user ID
   *
   * GET /security-events/user/:userId
   * Purpose: Get all security events for a specific user
   * Function: Retrieves security events filtered by user ID
   * Auth Required: Yes (Bearer token)
   * Description: Get security event history for a specific user
   *
   * @method GET
   * @param userId - User ID to filter events
   * @param response - Express response object
   * @param limit - Optional limit for results
   * @param page - Optional page for pagination
   * @returns Array of security events for the user
   */
  @Get("user/:userId")
  @ApiOperation({
    summary: "Get security events by user ID",
    description: "Retrieve all security events for a specific user"
  })
  async findByUserId(
    @Param("userId") userId: string,
    @Res() response: Response,
    @Query("limit") limit?: number,
    @Query("page") page?: number
  ) {
    try {
      const data = await this.securityEventService.findByUserId(userId, limit, page)

      generalResponse({
        response,
        message: "User security events retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get security events by event type
   *
   * GET /security-events/type/:eventType
   * Purpose: Get all security events of a specific type
   * Function: Retrieves security events filtered by event type
   * Auth Required: Yes (Bearer token)
   * Description: Get security events filtered by event type (e.g., LOGIN_FAILED, SUSPICIOUS_ACTIVITY)
   *
   * @method GET
   * @param eventType - Event type to filter by
   * @param response - Express response object
   * @param limit - Optional limit for results
   * @param page - Optional page for pagination
   * @returns Array of security events of the specified type
   */
  @Get("type/:eventType")
  @ApiOperation({
    summary: "Get security events by event type",
    description: "Retrieve all security events of a specific type"
  })
  async findByEventType(
    @Param("eventType") eventType: string,
    @Res() response: Response,
    @Query("limit") limit?: number,
    @Query("page") page?: number
  ) {
    try {
      const data = await this.securityEventService.findByEventType(eventType, limit, page)

      generalResponse({
        response,
        message: "Security events by type retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get security events by IP address
   *
   * GET /security-events/ip/:ipAddress
   * Purpose: Get all security events from a specific IP address
   * Function: Retrieves security events filtered by IP address
   * Auth Required: Yes (Bearer token)
   * Description: Get security event history for a specific IP address
   *
   * @method GET
   * @param ipAddress - IP address to filter events
   * @param response - Express response object
   * @param limit - Optional limit for results
   * @param page - Optional page for pagination
   * @returns Array of security events from the specified IP
   */
  @Get("ip/:ipAddress")
  @ApiOperation({
    summary: "Get security events by IP address",
    description: "Retrieve all security events from a specific IP address"
  })
  async findByIpAddress(
    @Param("ipAddress") ipAddress: string,
    @Res() response: Response,
    @Query("limit") limit?: number,
    @Query("page") page?: number
  ) {
    try {
      const data = await this.securityEventService.findByIpAddress(ipAddress, limit, page)

      generalResponse({
        response,
        message: "Security events by IP retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Create security event
   *
   * POST /security-events
   * Purpose: Create a new security event
   * Function: Creates a new security event in the database
   * Auth Required: Yes (Bearer token)
   * Description: Create a new security event record
   *
   * @method POST
   * @param createSecurityEventDto - Data for creating the security event
   * @param response - Express response object
   * @returns Created security event
   */
  @Post()
  @ApiOperation({
    summary: "Create security event",
    description: "Create a new security event record"
  })
  async create(@Body() createSecurityEventDto: any, @Res() response: Response) {
    try {
      const data = await this.securityEventService.create(createSecurityEventDto)

      generalResponse({
        response,
        message: "Security event created successfully",
        status: HttpStatus.CREATED,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Update security event
   *
   * PATCH /security-events/:id
   * Purpose: Update a specific security event
   * Function: Updates security event data in database
   * Auth Required: Yes (Bearer token)
   * Description: Update an existing security event record
   *
   * @method PATCH
   * @param id - Security event ID
   * @param updateSecurityEventDto - Data to update
   * @param response - Express response object
   * @returns Updated security event
   */
  @Patch(":id")
  @ApiOperation({
    summary: "Update security event",
    description: "Update an existing security event record"
  })
  async update(@Param("id") id: string, @Body() updateSecurityEventDto: any, @Res() response: Response) {
    try {
      const data = await this.securityEventService.update({ _id: id }, updateSecurityEventDto)

      generalResponse({
        response,
        message: "Security event updated successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Delete security event
   *
   * DELETE /security-events/:id
   * Purpose: Delete a specific security event
   * Function: Permanently removes security event from database
   * Auth Required: Yes (Bearer token)
   * Description: Delete an existing security event record
   *
   * @method DELETE
   * @param id - Security event ID
   * @param response - Express response object
   * @returns Success message
   */
  @Delete(":id")
  @ApiOperation({
    summary: "Delete security event",
    description: "Delete an existing security event record"
  })
  async remove(@Param("id") id: string, @Res() response: Response) {
    try {
      const data = await this.securityEventService.remove({ _id: id })

      generalResponse({
        response,
        message: "Security event deleted successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }
}
