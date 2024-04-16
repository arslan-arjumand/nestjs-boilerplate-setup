import { BadRequestException } from '@nestjs/common';
import { Document, Model, FilterQuery } from 'mongoose';
import { IFindQuery } from '../interface/entity.interface';

/**
 * Abstract class representing a repository for entities.
 * @template T - The type of the entity document.
 */
export abstract class EntityRepository<T extends Document> {
  constructor(protected readonly entityModel: Model<T>) {}

  /**
   * Creates a new entity.
   * @param createEntityData - The data to create the entity.
   * @returns A promise that resolves to the created entity.
   */
  async create(createEntityData: Partial<T>): Promise<T> {
    const entity = new this.entityModel(createEntityData);
    return entity.save();
  }

  /**
   * Finds a single entity based on the provided filter query and projection.
   * @param filterQuery - The filter query to find the entity.
   * @param projection - The projection to apply on the found entity.
   * @returns A promise that resolves to the found entity or null if not found.
   */
  async findOne(
    filterQuery: FilterQuery<T>,
    projection?: Record<string, unknown>,
  ): Promise<T | null> {
    return this.entityModel
      .findOne({ ...filterQuery }, { ...projection })
      .exec();
  }

  /**
   * Aggregates a list of entities based on the provided filter query, limit, and page.
   * @param filterQuery - The filter query to aggregate the entities.
   * @param limit - The maximum number of entities to return per page.
   * @param page - The page number.
   * @returns A promise that resolves to an object containing the aggregated data, count, page, limit, totalPage, and nextPage.
   */
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

  /**
   * Finds a list of entities based on the provided filter query, projection, populate, limit, sort, and select.
   * @param filterQuery - The filter query to find the entities.
   * @param projection - The projection to apply on the found entities.
   * @param populate - The fields to populate in the found entities.
   * @param limit - The maximum number of entities to return.
   * @param sort - The sorting criteria for the entities.
   * @param select - The fields to select in the found entities.
   * @returns A promise that resolves to an array of found entities.
   */
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

  /**
   * Finds a list of entities with pagination based on the provided filter query, projection, page, limit, populate, sort, and select.
   * @param filterQuery - The filter query to find the entities.
   * @param projection - The projection to apply on the found entities.
   * @param page - The page number.
   * @param limit - The maximum number of entities to return per page.
   * @param populate - The fields to populate in the found entities.
   * @param sort - The sorting criteria for the entities.
   * @param select - The fields to select in the found entities.
   * @returns A promise that resolves to an object containing the found entities, count, page, limit, totalPage, and nextPage.
   */
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

  /**
   * Searches for a list of entities based on the provided search string.
   * @param searchString - The search string to match against the entity name.
   * @returns A promise that resolves to an array of found entities.
   */
  async searchList(searchString: string): Promise<any> {
    return this.entityModel
      .find({ name: { $regex: searchString, $options: 'i' } } as any)
      .exec() as any;
  }

  /**
   * Finds and updates an entity based on the provided filter query and update data.
   * @param filterQuery - The filter query to find the entity.
   * @param updateEntityData - The data to update the entity.
   * @returns A promise that resolves to the updated entity or null if not found.
   * @throws BadRequestException if the entity is not found.
   */
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

  /**
   * Removes an entity based on the provided filter query.
   * @param filterQuery - The filter query to find the entity.
   * @returns A promise that resolves to the removed entity or unknown if not found.
   * @throws BadRequestException if the entity is not found.
   */
  async remove(filterQuery: FilterQuery<T>): Promise<T | unknown> {
    const data = await this.findOne(filterQuery);
    if (!data) {
      throw new BadRequestException('Invalid Data');
    }
    return this.entityModel.deleteOne(filterQuery).exec();
  }
}
