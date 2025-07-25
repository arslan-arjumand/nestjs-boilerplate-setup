import { Injectable } from "@nestjs/common"
import { SecurityEventRepository } from "../repository/security-event.repository"
import { EntityServices } from "@/modules/common/entity.service"
import { SecurityEvent } from "../schema/security-event.schema"

/**
 * Service responsible for handling security event-related operations.
 * Extends EntityServices for standard CRUD operations.
 */
@Injectable()
export class SecurityEventService extends EntityServices {
  /**
   * Creates an instance of SecurityEventService.
   * @param securityEventRepository The security event repository used for database operations.
   */
  constructor(private readonly securityEventRepository: SecurityEventRepository) {
    super(securityEventRepository)
  }

  /**
   * Creates a new security event.
   * @param createSecurityEventDto The DTO for creating the security event.
   * @returns The created security event.
   */
  async create(createSecurityEventDto: any): Promise<SecurityEvent> {
    return this.securityEventRepository.create(createSecurityEventDto)
  }

  /**
   * Updates a security event.
   * @param condition The condition for finding the security event.
   * @param updateSecurityEventDto The DTO for updating the security event.
   * @returns The updated security event.
   */
  async update(condition: object, updateSecurityEventDto: any): Promise<SecurityEvent | null> {
    return this.securityEventRepository.findOneAndUpdate(condition, updateSecurityEventDto)
  }

  /**
   * Find security events by user ID.
   * @param userId The user ID to filter by.
   * @param limit Optional limit for results.
   * @param page Optional page for pagination.
   * @returns Array of security events for the user.
   */
  async findByUserId(userId: string, limit?: number, page?: number): Promise<SecurityEvent[]> {
    return this.securityEventRepository.find({
      filterQuery: { userId },
      limit,
      page
    })
  }

  /**
   * Find security events by event type.
   * @param eventType The event type to filter by.
   * @param limit Optional limit for results.
   * @param page Optional page for pagination.
   * @returns Array of security events of the specified type.
   */
  async findByEventType(eventType: string, limit?: number, page?: number): Promise<SecurityEvent[]> {
    return this.securityEventRepository.find({
      filterQuery: { eventType },
      limit,
      page
    })
  }

  /**
   * Find security events by IP address.
   * @param ipAddress The IP address to filter by.
   * @param limit Optional limit for results.
   * @param page Optional page for pagination.
   * @returns Array of security events from the specified IP.
   */
  async findByIpAddress(ipAddress: string, limit?: number, page?: number): Promise<SecurityEvent[]> {
    return this.securityEventRepository.find({
      filterQuery: { ipAddress },
      limit,
      page
    })
  }
}
