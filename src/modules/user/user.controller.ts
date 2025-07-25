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
  BadRequestException,
  NotFoundException
} from "@nestjs/common"
import { AuthGuard } from "@nestjs/passport"
import { Response } from "express"
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger"
import { UserService } from "./service/user.service"
import { CreateUserDto, UpdateUserDto, UpdatePasswordDto } from "./dto"
import { GetUser, Roles } from "@/decorators"
import { compareHashValue, generalResponse, getHashValue } from "@/utils"
import { Users } from "./schema/user.schema"
import { UserRole } from "@/enums"

@ApiTags("Users")
@UseInterceptors(ClassSerializerInterceptor)
@Controller("user")
export class UserController {
  constructor(private readonly userService: UserService) {}

  /**
   * @description create user
   * @method POST
   * @param createUserDto
   * @return newly created user {}
   */
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN)
  @Post()
  async create(@Res() response: Response, @Body() createUserDto: CreateUserDto) {
    try {
      const data = await this.userService.create(createUserDto)

      generalResponse({
        response,
        message: "User created successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description get all users paginated
   * @method GET
   * @param page
   * @param limit
   * @return paginated users {}
   */
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN)
  @Get("paginated")
  async findAllPaginated(@Res() response: Response, @Query("page") page: number, @Query("limit") limit: number) {
    try {
      const data = await this.userService.findAllWithPagination({
        page: page || 1,
        limit: limit || 10
      })

      generalResponse({
        response,
        message: "Users found successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description get all users
   * @method GET
   * @return users {}
   */
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN)
  @Get()
  async findAll(@Res() response: Response) {
    try {
      const data = await this.userService.findAll({})

      generalResponse({
        response,
        message: "Users found successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description get a user by id
   * @method GET
   * @param id
   * @return user {}
   */
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  @Get(":id")
  async findOne(@Res() response: Response, @Param("id") id: string, @GetUser() currentUser: Users) {
    try {
      // Allow users to view their own profile or admins to view any profile
      if (currentUser.role === UserRole.USER && currentUser.id !== id) {
        throw new HttpException("Access denied: Can only view your own profile", HttpStatus.FORBIDDEN)
      }

      const data = await this.userService.findOne({ _id: id })
      if (!data) {
        throw new NotFoundException("Enter a valid User ID")
      }

      generalResponse({
        response,
        message: "User found successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description update user password
   * @method POST
   * @param updatePasswordDto
   * @return updated user {}
   */
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  @Post("change-password")
  async updatePassword(
    @Res() response: Response,
    @Body() updatePasswordDto: UpdatePasswordDto,
    @GetUser() user: Users
  ) {
    try {
      // Validate Password
      const compareHash = await compareHashValue(updatePasswordDto.currentPassword, user.password)
      if (!compareHash) {
        throw new BadRequestException("Invalid Credential")
      }
      // Update User
      const hashPassword = await getHashValue(updatePasswordDto.newPassword)
      const data = await this.userService.update({ _id: user.id }, { password: hashPassword })
      // Send Response
      generalResponse({
        response,
        message: "User password updated successfully",
        status: HttpStatus.OK,
        data: { ...data, httpStatus: HttpStatus.OK }
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description update user
   * @method PATCH
   * @param id
   * @param updateUserDto
   * @return updated user {}
   */
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN, UserRole.USER)
  @Patch(":id")
  async update(
    @Res() response: Response,
    @Param("id") id: string,
    @Body() updateUserDto: UpdateUserDto,
    @GetUser() currentUser: Users
  ) {
    try {
      // Allow users to update their own profile or admins to update any profile
      if (currentUser.role === UserRole.USER && currentUser.id !== id) {
        throw new HttpException("Access denied: Can only update your own profile", HttpStatus.FORBIDDEN)
      }

      // Prevent users from changing their own role, only admins can do that
      if (currentUser.role === UserRole.USER && updateUserDto.role) {
        throw new HttpException("Access denied: Cannot change your own role", HttpStatus.FORBIDDEN)
      }

      const data = await this.userService.update({ _id: id }, updateUserDto)

      generalResponse({
        response,
        message: "User updated successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }

  /**
   * @description delete user
   * @method DELETE
   * @param id
   * @return deleted user {}
   */
  @ApiBearerAuth()
  @UseGuards(AuthGuard("validate_token"))
  @Roles(UserRole.ADMIN)
  @Delete(":id")
  async remove(@Res() response: Response, @Param("id") id: string) {
    try {
      const data = await this.userService.remove({ _id: id })

      generalResponse({
        response,
        message: "User deleted successfully",
        status: HttpStatus.OK,
        data
      })
    } catch (error) {
      throw new HttpException(error["message"], error["status"])
    }
  }
}
