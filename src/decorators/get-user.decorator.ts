/**
 * Custom decorator to retrieve the authenticated user from the request object.
 * This decorator can be used to extract the user object from the request in NestJS controllers or route handlers.
 *
 * @param data - Additional data passed to the decorator (optional).
 * @param ctx - The execution context containing the request object.
 * @returns The authenticated user object.
 */
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Users } from 'src/modules/user/schema/user.schema';

export const GetUser = createParamDecorator(
  (data, ctx: ExecutionContext): Users => {
    const req = ctx.switchToHttp().getRequest();

    return req.user;
  },
);
