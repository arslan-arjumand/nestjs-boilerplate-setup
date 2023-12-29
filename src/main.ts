import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { HttpExceptionFilter } from './filters/http-exception.filter';
import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    cors: true,
  });

  const httpAdapterHost = app.get(HttpAdapterHost);
  app.setGlobalPrefix('api');
  app.useGlobalPipes(new ValidationPipe({ transform: true }));
  app.useGlobalFilters(new HttpExceptionFilter(httpAdapterHost));
  app.use(cookieParser());

  // Apply CORS Protection
  app.enableCors({
    // origin: [
    //   'http://localhost:3000',
    // ],
    origin: '*',
    methods: 'GET, PATCH, POST, DELETE',
    credentials: true,
  });

  // Apply Helmet Protection
  app.use(
    helmet({
      contentSecurityPolicy: false,
    }),
  );

  const configService = app.get(ConfigService);
  const port = process.env.PORT || Number(configService.get('PORT'));

  // Swagger Configuration
  const options = new DocumentBuilder()
    .addBearerAuth()
    .setTitle('Nest.js API')
    .setDescription('Nest.js APIs Documentation')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('api', app, document);

  await app.listen(port);
}

bootstrap();
