import { Module } from "@nestjs/common"
import { CacheService } from "./cache.service"

/**
 * Cache module that demonstrates how to use the shared Redis service
 * Since RedisModule is global, we don't need to import it here
 */
@Module({
  providers: [CacheService],
  exports: [CacheService]
})
export class CacheModule {}
