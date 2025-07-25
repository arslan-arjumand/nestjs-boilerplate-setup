import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from "@nestjs/common"
import Redis, { RedisOptions } from "ioredis"
import config from "@/config"

export interface RedisConfig extends RedisOptions {
  host?: string
  port?: number
  password?: string
  db?: number
  keyPrefix?: string
}

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name)
  private client: Redis
  private isConnected = false

  constructor() {
    const redisConfig: RedisConfig = {
      host: config.REDIS.HOST,
      port: config.REDIS.PORT,
      password: config.REDIS.PASSWORD,
      db: config.REDIS.DB,
      keyPrefix: config.REDIS.KEY_PREFIX,
      maxRetriesPerRequest: config.REDIS.MAX_RETRIES,
      connectTimeout: config.REDIS.CONNECT_TIMEOUT,
      lazyConnect: true,
      enableReadyCheck: true,
      commandTimeout: 5000,
      // TLS configuration for production
      tls: config.REDIS.TLS ? {} : undefined,
      // Connection pool settings
      family: 4, // IPv4
      keepAlive: 30000 // Keep alive for 30 seconds
    }

    this.client = new Redis(redisConfig)
    this.setupEventHandlers()
  }

  async onModuleInit() {
    await this.connect()
  }

  async onModuleDestroy() {
    await this.disconnect()
  }

  /**
   * Get the Redis client instance
   * @returns Redis client
   */
  getClient(): Redis {
    if (!this.isConnected) {
      throw new Error("Redis client is not connected")
    }
    return this.client
  }

  /**
   * Check if Redis is connected
   * @returns Connection status
   */
  isRedisConnected(): boolean {
    return this.isConnected && this.client.status === "ready"
  }

  /**
   * Connect to Redis
   */
  private async connect(): Promise<void> {
    try {
      await this.client.connect()
      this.logger.log(`Redis connected to ${config.REDIS.HOST}:${config.REDIS.PORT}`)
    } catch (error) {
      this.logger.error(`Failed to connect to Redis: ${error.message}`)
      throw error
    }
  }

  /**
   * Disconnect from Redis
   */
  private async disconnect(): Promise<void> {
    if (this.client) {
      try {
        await this.client.quit()
        this.logger.log("Redis connection closed gracefully")
      } catch (error) {
        this.logger.warn(`Warning during Redis disconnect: ${error.message}`)
      }
    }
  }

  /**
   * Setup Redis event handlers
   */
  private setupEventHandlers(): void {
    this.client.on("connect", () => {
      this.logger.log("Redis client connecting...")
    })

    this.client.on("ready", () => {
      this.isConnected = true
      this.logger.log("Redis client ready for commands")
    })

    this.client.on("error", (error) => {
      this.isConnected = false
      this.logger.error(`Redis client error: ${error.message}`)
    })

    this.client.on("close", () => {
      this.isConnected = false
      this.logger.warn("Redis connection closed")
    })

    this.client.on("reconnecting", (ms) => {
      this.logger.log(`Redis client reconnecting in ${ms}ms`)
    })

    this.client.on("end", () => {
      this.isConnected = false
      this.logger.log("Redis connection ended")
    })
  }

  // Convenience methods for common Redis operations

  /**
   * Get a value by key
   * @param key Redis key
   * @returns Value or null
   */
  async get(key: string): Promise<string | null> {
    try {
      return await this.client.get(key)
    } catch (error) {
      this.logger.error(`Error getting key ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Set a value with optional TTL
   * @param key Redis key
   * @param value Value to set
   * @param ttl TTL in seconds (optional)
   * @returns OK if successful
   */
  async set(key: string, value: string, ttl?: number): Promise<string> {
    try {
      if (ttl) {
        return await this.client.setex(key, ttl, value)
      }
      return await this.client.set(key, value)
    } catch (error) {
      this.logger.error(`Error setting key ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Set a value with expiration
   * @param key Redis key
   * @param ttl TTL in seconds
   * @param value Value to set
   * @returns OK if successful
   */
  async setex(key: string, ttl: number, value: string): Promise<string> {
    try {
      return await this.client.setex(key, ttl, value)
    } catch (error) {
      this.logger.error(`Error setting key ${key} with TTL: ${error.message}`)
      throw error
    }
  }

  /**
   * Delete one or more keys
   * @param keys Keys to delete
   * @returns Number of keys deleted
   */
  async del(...keys: string[]): Promise<number> {
    try {
      return await this.client.del(...keys)
    } catch (error) {
      this.logger.error(`Error deleting keys: ${error.message}`)
      throw error
    }
  }

  /**
   * Check if key exists
   * @param key Redis key
   * @returns 1 if exists, 0 otherwise
   */
  async exists(key: string): Promise<number> {
    try {
      return await this.client.exists(key)
    } catch (error) {
      this.logger.error(`Error checking key existence ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Get TTL of a key
   * @param key Redis key
   * @returns TTL in seconds, -1 if no expiration, -2 if key doesn't exist
   */
  async ttl(key: string): Promise<number> {
    try {
      return await this.client.ttl(key)
    } catch (error) {
      this.logger.error(`Error getting TTL for key ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Add members to a set
   * @param key Redis key
   * @param members Members to add
   * @returns Number of members added
   */
  async sadd(key: string, ...members: string[]): Promise<number> {
    try {
      return await this.client.sadd(key, ...members)
    } catch (error) {
      this.logger.error(`Error adding to set ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Remove members from a set
   * @param key Redis key
   * @param members Members to remove
   * @returns Number of members removed
   */
  async srem(key: string, ...members: string[]): Promise<number> {
    try {
      return await this.client.srem(key, ...members)
    } catch (error) {
      this.logger.error(`Error removing from set ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Get all members of a set
   * @param key Redis key
   * @returns Array of members
   */
  async smembers(key: string): Promise<string[]> {
    try {
      return await this.client.smembers(key)
    } catch (error) {
      this.logger.error(`Error getting set members ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Get the number of members in a set
   * @param key Redis key
   * @returns Number of members
   */
  async scard(key: string): Promise<number> {
    try {
      return await this.client.scard(key)
    } catch (error) {
      this.logger.error(`Error getting set cardinality ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Set expiration for a key
   * @param key Redis key
   * @param ttl TTL in seconds
   * @returns 1 if successful, 0 if key doesn't exist
   */
  async expire(key: string, ttl: number): Promise<number> {
    try {
      return await this.client.expire(key, ttl)
    } catch (error) {
      this.logger.error(`Error setting expiration for key ${key}: ${error.message}`)
      throw error
    }
  }

  /**
   * Find keys matching a pattern
   * @param pattern Pattern to match
   * @returns Array of matching keys
   */
  async keys(pattern: string): Promise<string[]> {
    try {
      return await this.client.keys(pattern)
    } catch (error) {
      this.logger.error(`Error finding keys with pattern ${pattern}: ${error.message}`)
      throw error
    }
  }

  /**
   * Execute Lua script
   * @param script Lua script
   * @param numKeys Number of keys
   * @param args Script arguments
   * @returns Script result
   */
  async eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<any> {
    try {
      return await this.client.eval(script, numKeys, ...args)
    } catch (error) {
      this.logger.error(`Error executing Lua script: ${error.message}`)
      throw error
    }
  }

  /**
   * Create a pipeline for batch operations
   * @returns Redis pipeline
   */
  pipeline() {
    return this.client.pipeline()
  }

  /**
   * Get Redis server info
   * @param section Optional section to get info for
   * @returns Redis info
   */
  async info(section?: string): Promise<string> {
    try {
      if (section) {
        return await this.client.info(section)
      }
      return await this.client.info()
    } catch (error) {
      this.logger.error(`Error getting Redis info: ${error.message}`)
      throw error
    }
  }

  /**
   * Ping Redis server
   * @returns PONG if successful
   */
  async ping(): Promise<string> {
    try {
      return await this.client.ping()
    } catch (error) {
      this.logger.error(`Error pinging Redis: ${error.message}`)
      throw error
    }
  }

  /**
   * Flush current database
   * @returns OK if successful
   */
  async flushdb(): Promise<string> {
    try {
      return await this.client.flushdb()
    } catch (error) {
      this.logger.error(`Error flushing database: ${error.message}`)
      throw error
    }
  }

  /**
   * Get memory usage of a key
   * @param key Redis key
   * @returns Memory usage in bytes
   */
  async memoryUsage(key: string): Promise<number> {
    try {
      const result = await this.client.memory("USAGE", key)
      return result || 0
    } catch (error) {
      this.logger.error(`Error getting memory usage for key ${key}: ${error.message}`)
      throw error
    }
  }
}
