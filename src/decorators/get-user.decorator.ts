import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Users } from 'src/modules/user/schema/user.schema';
// @schemas

export const GetUser = createParamDecorator(
  (data, ctx: ExecutionContext): Users => {
    const req = ctx.switchToHttp().getRequest();

    return req.user;
  },
);
