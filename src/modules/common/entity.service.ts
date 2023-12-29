import { Injectable } from '@nestjs/common';
import { EntityRepository } from './repository/entity.repository';
import { IEntity, IFindQuery } from './interface/entity.interface';

@Injectable()
export abstract class EntityServices {
  constructor(private readonly entityRepository: EntityRepository<IEntity>) {}

  async create(createEntityDto: unknown): Promise<IEntity> {
    return this.entityRepository.create(createEntityDto);
  }

  async findAll({
    filterQuery,
    projection,
    populate,
    limit,
    select,
    sort,
  }: IFindQuery) {
    return this.entityRepository.find({
      filterQuery,
      projection,
      populate,
      limit,
      sort,
      select,
    });
  }

  async aggregate({ filterQuery, limit, page }: IFindQuery) {
    return this.entityRepository.aggregate({
      filterQuery,
      page,
      limit,
    });
  }

  async findAllWithPagination({
    filterQuery,
    projection,
    populate,
    page,
    limit,
    sort,
    select,
  }: IFindQuery) {
    return this.entityRepository.findWithPagination({
      filterQuery,
      projection,
      populate,
      page,
      limit,
      sort,
      select,
    });
  }

  async findOne(
    condition: object,
    projection?: Record<string, unknown>,
  ): Promise<IEntity> {
    return this.entityRepository.findOne(condition, projection);
  }

  async searchList(searchString: string): Promise<IEntity[]> {
    return this.entityRepository.searchList(searchString);
  }

  async update(condition: object, updateEntityDto: unknown): Promise<IEntity> {
    return this.entityRepository.findOneAndUpdate(condition, updateEntityDto);
  }

  async remove(condition: object): Promise<IEntity | unknown> {
    return this.entityRepository.remove(condition);
  }
}
