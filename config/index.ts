import * as dotenv from 'dotenv';

dotenv.config();

export default () => ({
  PORT: +process.env.PORT || 3001,
  MONGO: {
    URL: process.env.MONGO_URI || '',
    logging: false,
    synchronize: true,
    migrationsRun: false,
    autoLoadEntites: true,
    entities: ['dist/src/modules/**/entities/*.entity{.ts,.js}'],
    migrations: ['dist/db/migrations/*.js'],
  },
  JWT: {
    JWT_SECRET_TOKEN: process.env.JWT_SECRET_TOKEN || '',
    JWT_TOKEN_EXPIRATION: process.env.JWT_TOKEN_EXPIRATION || '',
    JWT_SECRET_REFRESH_TOKEN: process.env.JWT_SECRET_REFRESH_TOKEN || '',
    JWT_REFRESH_TOKEN_EXPIRATION:
      process.env.JWT_REFRESH_TOKEN_EXPIRATION || '',
  },
  MAIL: {
    SERVER: process.env.MAIL_SERVER || '',
    HOST: process.env.MAIL_HOST || '',
    PORT: +process.env.MAIL_PORT || '',
    EMAIL: process.env.EMAIL || '',
    PASSWORD: process.env.PASSWORD || '',
  },
});
