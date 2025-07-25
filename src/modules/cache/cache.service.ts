import { Injectable, Logger } from "@nestjs/common"
import { RedisService } from "@/modules/redis/redis.service"

/**
 * Example service showing how to use the shared Redis service for caching
 * This demonstrates the reusability of the Redis connection across different modules
 */
@Injectable()
export class CacheService {
  private readonly logger = new Logger(CacheService.name)
  private readonly DEFAULT_TTL = 300 // 5 minutes

  constructor(private readonly redisService: RedisService) {}

  /**
   * Cache data with automatic JSON serialization
   * @param key Cache key
   * @param data Data to cache
   * @param ttl TTL in seconds (optional)
   */
  async set<T>(key: string, data: T, ttl: number = this.DEFAULT_TTL): Promise<void> {
    try {
      const serializedData = JSON.stringify(data)
      await this.redisService.setex(key, ttl, serializedData)
      this.logger.debug(`Cached data for key: ${key}`)
    } catch (error) {
      this.logger.error(`Error caching data for key ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Get cached data with automatic JSON deserialization
   * @param key Cache key
   * @returns Cached data or null
   */
  async get<T>(key: string): Promise<T | null> {
    try {
      const serializedData = await this.redisService.get(key)

      if (!serializedData) {
        return null
      }

      const data = JSON.parse(serializedData) as T
      this.logger.debug(`Retrieved cached data for key: ${key}`)
      return data
    } catch (error) {
      this.logger.error(`Error retrieving cached data for key ${key}: ${error.message}`)
      return null
    }
  }

  /**
   * Delete cached data
   * @param key Cache key
   * @returns True if deleted, false if key didn't exist
   */
  async delete(key: string): Promise<boolean> {
    try {
      const result = await this.redisService.del(key)
      this.logger.debug(`Deleted cache for key: ${key}`)
      return result > 0
    } catch (error) {
      this.logger.error(`Error deleting cache for key ${key}: ${error.message}`)
      return false
    }
  }

  /**
   * Check if key exists in cache
   * @param key Cache key
   * @returns True if exists
   */
  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.redisService.exists(key)
      return result === 1
    } catch (error) {
      this.logger.error(`Error checking existence for key ${key}: ${error.message}`)
      return false
    }
  }

  /**
   * Get or set cached data (cache-aside pattern)
   * @param key Cache key
   * @param fetcher Function to fetch data if not cached
   * @param ttl TTL in seconds (optional)
   * @returns Cached or freshly fetched data
   */
  async getOrSet<T>(key: string, fetcher: () => Promise<T>, ttl: number = this.DEFAULT_TTL): Promise<T> {
    try {
      // Try to get from cache first
      let data = await this.get<T>(key)

      if (data !== null) {
        this.logger.debug(`Cache hit for key: ${key}`)
        return data
      }

      // Cache miss - fetch data
      this.logger.debug(`Cache miss for key: ${key}`)
      data = await fetcher()

      // Cache the fetched data
      await this.set(key, data, ttl)

      return data
    } catch (error) {
      this.logger.error(`Error in getOrSet for key ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Invalidate cache by pattern
   * @param pattern Redis key pattern
   * @returns Number of keys deleted
   */
  async invalidatePattern(pattern: string): Promise<number> {
    try {
      const keys = await this.redisService.keys(pattern)

      if (keys.length === 0) {
        return 0
      }

      const deleted = await this.redisService.del(...keys)
      this.logger.debug(`Invalidated ${deleted} cache entries matching pattern: ${pattern}`)

      return deleted
    } catch (error) {
      this.logger.error(`Error invalidating cache pattern ${pattern}: ${error.message}`)
      throw error
    }
  }

  /**
   * Get cache statistics
   * @param prefix Key prefix to filter stats
   * @returns Cache statistics
   */
  async getStats(prefix: string = "*"): Promise<{
    totalKeys: number
    memoryUsage: string
    hitRate?: number
  }> {
    try {
      const keys = await this.redisService.keys(`${prefix}*`)
      const info = await this.redisService.info("memory")

      // Extract memory usage from info
      const memoryMatch = info.match(/used_memory_human:(.+)/i)
      const memoryUsage = memoryMatch ? memoryMatch[1].trim() : "Unknown"

      return {
        totalKeys: keys.length,
        memoryUsage
      }
    } catch (error) {
      this.logger.error(`Error getting cache stats: ${error.message}`)
      throw error
    }
  }

  /**
   * Warm up cache with data
   * @param entries Array of key-value pairs to cache
   * @param ttl TTL in seconds
   */
  async warmUp<T>(entries: Array<{ key: string; data: T }>, ttl: number = this.DEFAULT_TTL): Promise<void> {
    try {
      const pipeline = this.redisService.pipeline()

      for (const entry of entries) {
        const serializedData = JSON.stringify(entry.data)
        pipeline.setex(entry.key, ttl, serializedData)
      }

      await pipeline.exec()
      this.logger.log(`Cache warmed up with ${entries.length} entries`)
    } catch (error) {
      this.logger.error(`Error warming up cache: ${error.message}`)
      throw error
    }
  }
}
