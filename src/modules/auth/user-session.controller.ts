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
import { UserSessionService } from "./service/user-session.service"
import { QueryDto } from "@/modules/common/interface/entity.interface"
import { generalResponse } from "@/utils"
import { Roles } from "@/decorators"
import { UserRole } from "@/enums"

@ApiTags("User Sessions")
@ApiBearerAuth()
@UseGuards(AuthGuard("validate_token"))
@Roles(UserRole.ADMIN)
@UseInterceptors(ClassSerializerInterceptor)
@Controller("user-sessions")
export class UserSessionController {
  constructor(private readonly userSessionService: UserSessionService) {}

  /**
   * Get all user sessions with pagination
   *
   * GET /user-sessions
   * Purpose: Get all user sessions with pagination support
   * Function: Retrieves paginated list of all user sessions from database
   * Auth Required: Yes (Bearer token)
   * Description: Admin endpoint to view all user sessions with pagination
   *
   * @method GET
   * @param query - Pagination query parameters
   * @param response - Express response object
   * @returns Paginated list of user sessions
   */
  @Get()
  @ApiOperation({
    summary: "Get all user sessions with pagination",
    description: "Retrieve all user sessions with pagination support"
  })
  async findAllPaginated(@Res() response: Response, @Query() query: QueryDto) {
    try {
      const data = await this.userSessionService.findAllWithPagination({
        page: query.page || 1,
        limit: query.limit || 25
      })

      generalResponse({
        response,
        message: "User sessions retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get user session by ID
   *
   * GET /user-sessions/:id
   * Purpose: Get a specific user session by ID
   * Function: Retrieves complete user session data from database
   * Auth Required: Yes (Bearer token)
   * Description: Retrieve detailed information about a specific user session
   *
   * @method GET
   * @param id - User session ID
   * @param response - Express response object
   * @returns User session document
   */
  @Get(":id")
  @ApiOperation({
    summary: "Get user session by ID",
    description: "Retrieve a specific user session by its ID"
  })
  async findOne(@Param("id") id: string, @Res() response: Response) {
    try {
      const data = await this.userSessionService.findOne({ _id: id })
      if (!data) {
        throw new NotFoundException("User session not found")
      }

      generalResponse({
        response,
        message: "User session retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get user sessions by user ID
   *
   * GET /user-sessions/user/:userId
   * Purpose: Get all user sessions for a specific user
   * Function: Retrieves user sessions filtered by user ID
   * Auth Required: Yes (Bearer token)
   * Description: Get session history for a specific user
   *
   * @method GET
   * @param userId - User ID to filter sessions
   * @param response - Express response object
   * @param limit - Optional limit for results
   * @param page - Optional page for pagination
   * @returns Array of user sessions for the user
   */
  @Get("user/:userId")
  @ApiOperation({
    summary: "Get user sessions by user ID",
    description: "Retrieve all user sessions for a specific user"
  })
  async findByUserId(
    @Param("userId") userId: string,
    @Res() response: Response,
    @Query("limit") limit?: number,
    @Query("page") page?: number
  ) {
    try {
      const data = await this.userSessionService.findByUserId(userId, limit, page)

      generalResponse({
        response,
        message: "User sessions retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get active user sessions by user ID
   *
   * GET /user-sessions/user/:userId/active
   * Purpose: Get all active user sessions for a specific user
   * Function: Retrieves active user sessions filtered by user ID
   * Auth Required: Yes (Bearer token)
   * Description: Get currently active sessions for a specific user
   *
   * @method GET
   * @param userId - User ID to filter sessions
   * @param response - Express response object
   * @param limit - Optional limit for results
   * @param page - Optional page for pagination
   * @returns Array of active user sessions for the user
   */
  @Get("user/:userId/active")
  @ApiOperation({
    summary: "Get active user sessions by user ID",
    description: "Retrieve all active user sessions for a specific user"
  })
  async findActiveByUserId(
    @Param("userId") userId: string,
    @Res() response: Response,
    @Query("limit") limit?: number,
    @Query("page") page?: number
  ) {
    try {
      const data = await this.userSessionService.findActiveByUserId(userId, limit, page)

      generalResponse({
        response,
        message: "Active user sessions retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get user sessions by status
   *
   * GET /user-sessions/status/:status
   * Purpose: Get all user sessions with a specific status
   * Function: Retrieves user sessions filtered by status
   * Auth Required: Yes (Bearer token)
   * Description: Get user sessions filtered by status (ACTIVE, EXPIRED, TERMINATED, REVOKED)
   *
   * @method GET
   * @param status - Session status to filter by
   * @param response - Express response object
   * @param limit - Optional limit for results
   * @param page - Optional page for pagination
   * @returns Array of user sessions with the specified status
   */
  @Get("status/:status")
  @ApiOperation({
    summary: "Get user sessions by status",
    description: "Retrieve all user sessions with a specific status"
  })
  async findByStatus(
    @Param("status") status: string,
    @Res() response: Response,
    @Query("limit") limit?: number,
    @Query("page") page?: number
  ) {
    try {
      const data = await this.userSessionService.findByStatus(status, limit, page)

      generalResponse({
        response,
        message: "User sessions by status retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get user sessions by IP address
   *
   * GET /user-sessions/ip/:ipAddress
   * Purpose: Get all user sessions from a specific IP address
   * Function: Retrieves user sessions filtered by IP address
   * Auth Required: Yes (Bearer token)
   * Description: Get session history for a specific IP address
   *
   * @method GET
   * @param ipAddress - IP address to filter sessions
   * @param response - Express response object
   * @param limit - Optional limit for results
   * @param page - Optional page for pagination
   * @returns Array of user sessions from the specified IP
   */
  @Get("ip/:ipAddress")
  @ApiOperation({
    summary: "Get user sessions by IP address",
    description: "Retrieve all user sessions from a specific IP address"
  })
  async findByIpAddress(
    @Param("ipAddress") ipAddress: string,
    @Res() response: Response,
    @Query("limit") limit?: number,
    @Query("page") page?: number
  ) {
    try {
      const data = await this.userSessionService.findByIpAddress(ipAddress, limit, page)

      generalResponse({
        response,
        message: "User sessions by IP retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get user session by session ID
   *
   * GET /user-sessions/session/:sessionId
   * Purpose: Get a specific user session by session ID
   * Function: Retrieves user session by session ID
   * Auth Required: Yes (Bearer token)
   * Description: Find a user session using its unique session ID
   *
   * @method GET
   * @param sessionId - Session ID to find
   * @param response - Express response object
   * @returns User session with the specified session ID
   */
  @Get("session/:sessionId")
  @ApiOperation({
    summary: "Get user session by session ID",
    description: "Retrieve a specific user session by its session ID"
  })
  async findBySessionId(@Param("sessionId") sessionId: string, @Res() response: Response) {
    try {
      const data = await this.userSessionService.findBySessionId(sessionId)
      if (!data) {
        throw new NotFoundException("User session not found")
      }

      generalResponse({
        response,
        message: "User session retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Get expired user sessions
   *
   * GET /user-sessions/expired
   * Purpose: Get all expired user sessions
   * Function: Retrieves user sessions that are expired or past expiration date
   * Auth Required: Yes (Bearer token)
   * Description: Get user sessions that need cleanup or are expired
   *
   * @method GET
   * @param response - Express response object
   * @param limit - Optional limit for results
   * @param page - Optional page for pagination
   * @returns Array of expired user sessions
   */
  @Get("expired")
  @ApiOperation({
    summary: "Get expired user sessions",
    description: "Retrieve all expired user sessions"
  })
  async findExpired(@Res() response: Response, @Query("limit") limit?: number, @Query("page") page?: number) {
    try {
      const data = await this.userSessionService.findExpired(limit, page)

      generalResponse({
        response,
        message: "Expired user sessions retrieved successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Create user session
   *
   * POST /user-sessions
   * Purpose: Create a new user session
   * Function: Creates a new user session in the database
   * Auth Required: Yes (Bearer token)
   * Description: Create a new user session record
   *
   * @method POST
   * @param createUserSessionDto - Data for creating the user session
   * @param response - Express response object
   * @returns Created user session
   */
  @Post()
  @ApiOperation({
    summary: "Create user session",
    description: "Create a new user session record"
  })
  async create(@Body() createUserSessionDto: any, @Res() response: Response) {
    try {
      const data = await this.userSessionService.create(createUserSessionDto)

      generalResponse({
        response,
        message: "User session created successfully",
        status: HttpStatus.CREATED,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Update user session
   *
   * PATCH /user-sessions/:id
   * Purpose: Update a specific user session
   * Function: Updates user session data in database
   * Auth Required: Yes (Bearer token)
   * Description: Update an existing user session record
   *
   * @method PATCH
   * @param id - User session ID
   * @param updateUserSessionDto - Data to update
   * @param response - Express response object
   * @returns Updated user session
   */
  @Patch(":id")
  @ApiOperation({
    summary: "Update user session",
    description: "Update an existing user session record"
  })
  async update(@Param("id") id: string, @Body() updateUserSessionDto: any, @Res() response: Response) {
    try {
      const data = await this.userSessionService.update({ _id: id }, updateUserSessionDto)

      generalResponse({
        response,
        message: "User session updated successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }

  /**
   * Delete user session
   *
   * DELETE /user-sessions/:id
   * Purpose: Delete a specific user session
   * Function: Permanently removes user session from database
   * Auth Required: Yes (Bearer token)
   * Description: Delete an existing user session record
   *
   * @method DELETE
   * @param id - User session ID
   * @param response - Express response object
   * @returns Success message
   */
  @Delete(":id")
  @ApiOperation({
    summary: "Delete user session",
    description: "Delete an existing user session record"
  })
  async remove(@Param("id") id: string, @Res() response: Response) {
    try {
      const data = await this.userSessionService.remove({ _id: id })

      generalResponse({
        response,
        message: "User session deleted successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR)
    }
  }
}
