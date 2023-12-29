import { BadRequestException } from '@nestjs/common';
import { Document, Model, FilterQuery } from 'mongoose';
// @Interface
import { IFindQuery } from '../interface/entity.interface';

export abstract class EntityRepository<T extends Document> {
  constructor(protected readonly entityModel: Model<T>) {}

  // create new entity
  async create(createEntityData: Partial<T>): Promise<T> {
    const entity = new this.entityModel(createEntityData);
    return entity.save();
  }

  // find single entity
  async findOne(
    filterQuery: FilterQuery<T>,
    projection?: Record<string, unknown>,
  ): Promise<T | null> {
    return this.entityModel
      .findOne({ ...filterQuery }, { ...projection })
      .exec();
  }

  // aggregate entity list
  async aggregate({ filterQuery, limit, page }: IFindQuery) {
    const currentPage = page - 1;

    const data = await this.entityModel
      .aggregate(filterQuery)
      .skip(limit * currentPage)
      .limit(limit)
      .exec();

    // find count
    const count = (await this.entityModel.aggregate(filterQuery)).length;

    const totalPage = Math.ceil(count / limit);

    return {
      data,
      count,
      page,
      limit,
      totalPage,
      nextPage: page < totalPage ? page + 1 : null,
    };
  }

  // find entity list
  async find({
    filterQuery,
    projection,
    populate,
    limit,
    sort,
    select,
  }: IFindQuery) {
    return this.entityModel
      .find(
        {
          ...filterQuery,
        },
        { ...projection },
      )
      .populate(populate)
      .limit(limit)
      .sort(sort)
      .select(select)
      .exec();
  }

  // find entity list with pagination
  async findWithPagination({
    filterQuery,
    projection,
    page = 1,
    limit = 25,
    populate,
    sort,
    select,
  }: IFindQuery) {
    const currentPage = page - 1;

    // find list
    const data = await this.entityModel
      .find({ ...filterQuery }, { ...projection })
      .populate(populate)
      .skip(limit * currentPage)
      .limit(limit)
      .sort(sort)
      .select(select)
      .exec();

    // find count
    const count = await this.entityModel
      .find()
      .where({
        ...filterQuery,
      })
      .countDocuments()
      .exec();

    const totalPage = Math.ceil(count / limit);

    return {
      data,
      count,
      page,
      limit,
      totalPage,
      nextPage: page < totalPage ? page + 1 : null,
    };
  }

  // search entity list
  async searchList(searchString: string): Promise<T[] | null> {
    return this.entityModel
      .find({ name: { $regex: searchString, $options: 'i' } })
      .exec();
  }

  // update entity
  async findOneAndUpdate(
    filterQuery: FilterQuery<T>,
    updateEntityData: Partial<T>,
  ): Promise<T | null> {
    const data = await this.findOne(filterQuery);
    if (!data) {
      throw new BadRequestException('Invalid Data');
    }
    return this.entityModel
      .findOneAndUpdate(
        filterQuery,
        {
          $set: updateEntityData,
        },
        { new: true },
      )
      .exec();
  }

  // remove entity
  async remove(filterQuery: FilterQuery<T>): Promise<T | unknown> {
    const data = await this.findOne(filterQuery);
    if (!data) {
      throw new BadRequestException('Invalid Data');
    }
    return this.entityModel.deleteOne(filterQuery).exec();
  }
}
