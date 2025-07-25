import { Injectable, CanActivate, ExecutionContext, ForbiddenException, Logger } from "@nestjs/common"
import { Reflector } from "@nestjs/core"
import { UserRole } from "@/enums"
import { ROLES_KEY } from "@/decorators/roles.decorator"
import { Users } from "@/modules/user/schema/user.schema"

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name)

  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (!requiredRoles) {
      return true
    }

    const { user }: { user: Users } = context.switchToHttp().getRequest()

    if (!user) {
      this.logger.warn("No user found in request context")
      throw new ForbiddenException("Access denied: Authentication required")
    }

    if (!user.role) {
      this.logger.warn(`User ${user.id} has no role assigned`)
      throw new ForbiddenException("Access denied: No role assigned")
    }

    const hasRole = requiredRoles.some((role) => user.role === role)

    if (!hasRole) {
      this.logger.warn(
        `User ${user.id} with role ${user.role} attempted to access endpoint requiring roles: ${requiredRoles.join(", ")}`
      )
      throw new ForbiddenException(`Access denied: Required role(s): ${requiredRoles.join(", ")}`)
    }

    this.logger.log(`User ${user.id} with role ${user.role} granted access`)
    return true
  }
}
