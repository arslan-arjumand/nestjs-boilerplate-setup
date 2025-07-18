/**
 * A parameter decorator that extracts the user object from the request.
 * This decorator can be used to get the currently authenticated user.
 * @param data - Optional parameter to specify which property of the user to extract.
 * @param ctx - The execution context.
 * @returns The user object or a specific property of the user.
 */
import { createParamDecorator, ExecutionContext } from "@nestjs/common"
import { Users } from "@/modules/user/schema/user.schema"

export const GetUser = createParamDecorator((data: string, ctx: ExecutionContext): Users => {
  const req = ctx.switchToHttp().getRequest()
  const user = req.user

  return data ? user?.[data] : user
})
