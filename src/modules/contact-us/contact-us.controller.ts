import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseInterceptors,
  ClassSerializerInterceptor,
  UseGuards,
  Res,
  HttpStatus,
  HttpException,
  NotFoundException,
  Query,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
// @Services
import { ContactUsService } from './service/contact-us.service';
// @Dto
import { CreateContactUsDto, UpdateContactUsDto } from './dto';
// @Utils
import { generalResponse } from 'src/utils';

@ApiTags('Contact Us')
@UseInterceptors(ClassSerializerInterceptor)
@Controller('contact-us')
export class ContactUsController {
  constructor(private readonly contactUsService: ContactUsService) {}

  /**
   * @description create contact-us
   * @method POST
   * @param createContactUsDto
   * @return newly created contact-us {}
   */
  // @ApiBearerAuth()
  // @UseGuards(AuthGuard('validate_token'))
  @Post()
  async create(
    @Res() response: Response,
    @Body() createContactUsDto: CreateContactUsDto,
  ) {
    try {
      const data = await this.contactUsService.create(createContactUsDto);

      generalResponse({
        response,
        message: 'Contact Us created successfully',
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard('validate_token'))
  @Get('paginated')
  async findAllPaginated(
    @Res() response: Response,
    @Query('page') page: number,
    @Query('limit') limit: number,
  ) {
    try {
      const data = await this.contactUsService.findAllWithPagination({
        page: page || 1,
        limit: limit || 10,
      });

      generalResponse({
        response,
        message: 'Records found successfully',
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard('validate_token'))
  @Get()
  async findAll(@Res() response: Response) {
    try {
      const data = await this.contactUsService.findAll({});

      generalResponse({
        response,
        message: 'Contact Us found successfully',
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard('validate_token'))
  @Get(':id')
  async findOne(@Res() response: Response, @Param('id') id: string) {
    try {
      const data = await this.contactUsService.findOne({ _id: id });
      if (!data) {
        throw new NotFoundException('Enter a valid Contact Us ID');
      }

      generalResponse({
        response,
        message: 'Contact Us found successfully',
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard('validate_token'))
  @Patch(':id')
  async update(
    @Res() response: Response,
    @Param('id') id: string,
    @Body() updateContactUsDto: UpdateContactUsDto,
  ) {
    try {
      const data = await this.contactUsService.update(
        { _id: id },
        updateContactUsDto,
      );

      generalResponse({
        response,
        message: 'Contact Us updated successfully',
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard('validate_token'))
  @Delete(':id')
  async remove(@Res() response: Response, @Param('id') id: string) {
    try {
      const data = await this.contactUsService.remove({ _id: id });

      generalResponse({
        response,
        message: 'Contact Us deleted successfully',
        status: HttpStatus.OK,
        data,
      });
    } catch (error) {
      throw new HttpException(error['message'], error['status']);
    }
  }
}
