import { Injectable, UnauthorizedException } from "@nestjs/common"
import { PassportStrategy } from "@nestjs/passport"
import { ExtractJwt, Strategy } from "passport-jwt"
import { AuthRepository } from "../repository/auth.repository"
import { RedisTokenBlacklistService } from "../service/redis-token-blacklist.service"
import { SessionManagerService } from "../service/session-manager.service"
import { Request } from "express"
import config from "@/config"

const { JWT_SECRET_TOKEN, JWT_REFRESH_TOKEN } = config.JWT

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, "validate_token") {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly tokenBlacklistService: RedisTokenBlacklistService,
    private readonly sessionManager: SessionManagerService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: Buffer.from(JWT_REFRESH_TOKEN, "base64").toString("utf8"),
      algorithms: ["RS256"],
      passReqToCallback: true // This allows us to access the request object
    })
  }

  async validate(req: Request) {
    try {
      // Extract token from Authorization header only (more secure)
      const authHeader = req.headers["authorization"]

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        throw new UnauthorizedException("Missing or invalid authorization header")
      }

      const token = authHeader.split(" ")[1]

      if (!token || token === "undefined" || token === "null") {
        throw new UnauthorizedException("No access token provided")
      }

      // Check if token is blacklisted
      const isBlacklisted = await this.tokenBlacklistService.isTokenBlacklisted(token)
      if (isBlacklisted) {
        throw new UnauthorizedException("Token has been revoked")
      }

      // Use the proper verification method from repository
      const user: any = await this.authRepository.verifyAccessToken(token)

      // Check if account is locked
      if (user.locked_until && new Date() < user.locked_until) {
        throw new UnauthorizedException("Account is temporarily locked")
      }

      // Update session activity if session ID is available
      const sessionId = (req as any).sessionId
      if (sessionId) {
        try {
          await this.sessionManager.updateSessionActivity(sessionId, req)
        } catch (error) {
          // Don't fail authentication if session update fails, just log
          console.warn(`Failed to update session activity for ${sessionId}:`, error.message)
        }
      }

      // Attach token and session info to request for potential revocation
      req["token"] = token
      req["user"] = user

      // Try to extract session ID from token metadata if not already set
      if (!sessionId) {
        try {
          const decoded = this.authRepository.jwtService.decode(token) as any
          if (decoded?.sessionId) {
            req["sessionId"] = decoded.sessionId
            await this.sessionManager.updateSessionActivity(decoded.sessionId, req)
          }
        } catch (error) {
          // Ignore session ID extraction errors
        }
      }

      return user
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error
      }
      throw new UnauthorizedException("Authentication failed")
    }
  }
}
