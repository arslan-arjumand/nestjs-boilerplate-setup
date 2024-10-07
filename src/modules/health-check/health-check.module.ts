import { Module } from '@nestjs/common';
// @Controller
import { HealthCheckController } from './health-check.controller';

@Module({
  controllers: [HealthCheckController],
})
export class HealthCheckModule {}
