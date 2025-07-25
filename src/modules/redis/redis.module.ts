import { Module, Global } from "@nestjs/common"
import { RedisService } from "./redis.service"

/**
 * Global Redis module that provides Redis connectivity across the application
 * This module is marked as @Global so it doesn't need to be imported in every module
 */
@Global()
@Module({
  providers: [RedisService],
  exports: [RedisService]
})
export class RedisModule {
  /**
   * Create a forRoot method for advanced configuration if needed
   * @param options Redis configuration options
   * @returns Dynamic module
   */
  static forRoot(options?: any) {
    return {
      module: RedisModule,
      providers: [
        {
          provide: "REDIS_OPTIONS",
          useValue: options || {}
        },
        RedisService
      ],
      exports: [RedisService]
    }
  }
}
