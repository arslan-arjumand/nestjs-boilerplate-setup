import { HttpAdapterHost, NestFactory } from "@nestjs/core"
import { AppModule } from "./app.module"
import { ValidationPipe } from "@nestjs/common"
import { HttpExceptionFilter } from "@/filters/http-exception.filter"
import * as cookieParser from "cookie-parser"
import helmet from "helmet"
import * as compression from "compression"
import config from "@/config"
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger"

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    cors: {
      origin: "*",
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true
    }
  })

  // Set up global exception filter
  const httpAdapterHost = app.get(HttpAdapterHost)

  // Set global prefix for all routes
  app.setGlobalPrefix("api")

  // Apply global validation pipe to transform incoming data
  app.useGlobalPipes(new ValidationPipe({ transform: true }))

  // Apply global exception filter to handle HTTP exceptions
  app.useGlobalFilters(new HttpExceptionFilter(httpAdapterHost))

  // Parse cookies in incoming requests
  app.use(cookieParser())

  // Apply Helmet protection middleware
  app.use(
    helmet({
      contentSecurityPolicy: false
    })
  )

  // Apply compression middleware
  app.use(compression())

  // Configure Swagger documentation
  const options = new DocumentBuilder()
    .addBearerAuth()
    .setTitle("API")
    .setDescription("API Documentation")
    .setVersion("1.0")
    .build()

  const document = SwaggerModule.createDocument(app, options)
  // Set '/' route for Swagger documentation
  SwaggerModule.setup("/", app, document)

  // Get port from config
  const port = +config.SERVER.PORT

  // Start the server
  await app.listen(port)
}

bootstrap()
