import { Injectable, UnauthorizedException, Req } from "@nestjs/common"
import { PassportStrategy } from "@nestjs/passport"
import { Strategy } from "passport-custom"
import { JwtService } from "@nestjs/jwt"
import { Request } from "express"
import { UserService } from "@/modules/user/service/user.service"
import { AuthRepository } from "../repository/auth.repository"

/**
 * Validates the JWT token and returns the authenticated user.
 * Throws an UnauthorizedException if the token is invalid or the user is not found.
 *
 * @param req - The HTTP request object.
 * @returns The authenticated user.
 * @throws UnauthorizedException if the token is invalid or the user is not found.
 */
@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, "validate_token") {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly authRepository: AuthRepository
  ) {
    super()
  }

  async validate(@Req() req: Request) {
    try {
      // Extract token from Authorization header only (more secure)
      const authHeader = req.headers["authorization"]
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new UnauthorizedException("Missing or invalid authorization header")
      }

      const token = authHeader.split(" ")[1]

      if (!token || token === "undefined" || token === "null") {
        throw new UnauthorizedException("No access token provided")
      }

      // Use the proper verification method from repository
      const user: any = await this.authRepository.verifyAccessToken(token)
      
      // Check if account is locked
      if (user.locked_until && new Date() < user.locked_until) {
        throw new UnauthorizedException("Account is temporarily locked")
      }

      // Attach token to request for potential revocation
      req["token"] = token
      req["user"] = user

      return user
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error
      }
      throw new UnauthorizedException("Authentication failed")
    }
  }
}
