import { Injectable } from "@nestjs/common"
import { UserSessionRepository } from "../repository/user-session.repository"
import { EntityServices } from "@/modules/common/entity.service"
import { UserSession } from "../schema/user-session.schema"

/**
 * Service responsible for handling user session-related operations.
 * Extends EntityServices for standard CRUD operations.
 */
@Injectable()
export class UserSessionService extends EntityServices {
  /**
   * Creates an instance of UserSessionService.
   * @param userSessionRepository The user session repository used for database operations.
   */
  constructor(private readonly userSessionRepository: UserSessionRepository) {
    super(userSessionRepository)
  }

  /**
   * Creates a new user session.
   * @param createUserSessionDto The DTO for creating the user session.
   * @returns The created user session.
   */
  async create(createUserSessionDto: any): Promise<UserSession> {
    return this.userSessionRepository.create(createUserSessionDto)
  }

  /**
   * Updates a user session.
   * @param condition The condition for finding the user session.
   * @param updateUserSessionDto The DTO for updating the user session.
   * @returns The updated user session.
   */
  async update(condition: object, updateUserSessionDto: any): Promise<UserSession | null> {
    return this.userSessionRepository.findOneAndUpdate(condition, updateUserSessionDto)
  }

  /**
   * Find user sessions by user ID.
   * @param userId The user ID to filter by.
   * @param limit Optional limit for results.
   * @param page Optional page for pagination.
   * @returns Array of user sessions for the user.
   */
  async findByUserId(userId: string, limit?: number, page?: number): Promise<UserSession[]> {
    return this.userSessionRepository.find({
      filterQuery: { userId },
      limit,
      page
    })
  }

  /**
   * Find user sessions by session status.
   * @param status The session status to filter by.
   * @param limit Optional limit for results.
   * @param page Optional page for pagination.
   * @returns Array of user sessions with the specified status.
   */
  async findByStatus(status: string, limit?: number, page?: number): Promise<UserSession[]> {
    return this.userSessionRepository.find({
      filterQuery: { status },
      limit,
      page
    })
  }

  /**
   * Find user sessions by IP address.
   * @param ipAddress The IP address to filter by.
   * @param limit Optional limit for results.
   * @param page Optional page for pagination.
   * @returns Array of user sessions from the specified IP.
   */
  async findByIpAddress(ipAddress: string, limit?: number, page?: number): Promise<UserSession[]> {
    return this.userSessionRepository.find({
      filterQuery: { ipAddress },
      limit,
      page
    })
  }

  /**
   * Find user sessions by session ID.
   * @param sessionId The session ID to find.
   * @returns The user session with the specified session ID or null.
   */
  async findBySessionId(sessionId: string): Promise<UserSession | null> {
    return this.userSessionRepository.findOne({ sessionId })
  }

  /**
   * Find active user sessions for a user.
   * @param userId The user ID to filter by.
   * @param limit Optional limit for results.
   * @param page Optional page for pagination.
   * @returns Array of active user sessions for the user.
   */
  async findActiveByUserId(userId: string, limit?: number, page?: number): Promise<UserSession[]> {
    return this.userSessionRepository.find({
      filterQuery: { userId, status: "ACTIVE" },
      limit,
      page
    })
  }

  /**
   * Find expired user sessions.
   * @param limit Optional limit for results.
   * @param page Optional page for pagination.
   * @returns Array of expired user sessions.
   */
  async findExpired(limit?: number, page?: number): Promise<UserSession[]> {
    return this.userSessionRepository.find({
      filterQuery: {
        $or: [{ status: "EXPIRED" }, { expiresAt: { $lt: new Date() } }]
      },
      limit,
      page
    })
  }
}
