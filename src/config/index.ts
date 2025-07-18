import * as dotenv from "dotenv"

dotenv.config({
  path: ".env",
  quiet: true
})

// Environment-specific security configurations
const getSecurityConfig = (environment: string) => {
  switch (environment) {
    case "development":
      return {
        // 🔧 Development: Longer tokens for convenience
        JWT_TOKEN_EXPIRATION: "1h",
        JWT_REFRESH_TOKEN_EXPIRATION: "30d",
        PASSWORD_RESET_EXPIRY: 60 * 60 * 1000, // 1 hour
        MAX_LOGIN_ATTEMPTS: 10,
        ACCOUNT_LOCK_TIME: 5 * 60 * 1000 // 5 minutes
      }

    case "production":
      return {
        // 🔒 Production: Maximum security
        JWT_TOKEN_EXPIRATION: "15m",
        JWT_REFRESH_TOKEN_EXPIRATION: "7d",
        PASSWORD_RESET_EXPIRY: 15 * 60 * 1000, // 15 minutes
        MAX_LOGIN_ATTEMPTS: 5,
        ACCOUNT_LOCK_TIME: 15 * 60 * 1000 // 15 minutes
      }

    case "staging":
      return {
        // 🧪 Staging: Balanced for testing
        JWT_TOKEN_EXPIRATION: "30m",
        JWT_REFRESH_TOKEN_EXPIRATION: "14d",
        PASSWORD_RESET_EXPIRY: 30 * 60 * 1000, // 30 minutes
        MAX_LOGIN_ATTEMPTS: 7,
        ACCOUNT_LOCK_TIME: 10 * 60 * 1000 // 10 minutes
      }

    default:
      return {
        // 🛡️ Default: Production security
        JWT_TOKEN_EXPIRATION: "15m",
        JWT_REFRESH_TOKEN_EXPIRATION: "7d",
        PASSWORD_RESET_EXPIRY: 15 * 60 * 1000,
        MAX_LOGIN_ATTEMPTS: 5,
        ACCOUNT_LOCK_TIME: 15 * 60 * 1000
      }
  }
}

const environment = process.env.ENVIRONMENT || "development"
const envSecurity = getSecurityConfig(environment)

export default {
  SERVER: {
    ENVIRONMENT: environment,
    PORT: process.env.PORT || 3001
  },
  MONGO: {
    URL: process.env.MONGO_URL || "",
    DB_NAME: process.env.MONGO_DB_NAME || ""
  },
  JWT: {
    // Access Token: Environment-specific expiration
    JWT_SECRET_TOKEN: process.env.JWT_SECRET_TOKEN || "",
    JWT_TOKEN_EXPIRATION: envSecurity.JWT_TOKEN_EXPIRATION,

    // Refresh Token: Environment-specific expiration
    JWT_SECRET_REFRESH_TOKEN: process.env.JWT_SECRET_REFRESH_TOKEN || "",
    JWT_REFRESH_TOKEN_EXPIRATION: envSecurity.JWT_REFRESH_TOKEN_EXPIRATION
  },
  MAIL: {
    SERVER: process.env.MAIL_SERVER || "",
    HOST: process.env.MAIL_HOST || "",
    PORT: process.env.MAIL_PORT || "",
    EMAIL: process.env.EMAIL || "",
    PASSWORD: process.env.PASSWORD || ""
  },
  SECURITY: {
    // Password Reset Token: Environment-specific expiration
    PASSWORD_RESET_EXPIRY: envSecurity.PASSWORD_RESET_EXPIRY,

    // Account Locking: Environment-specific configuration
    MAX_LOGIN_ATTEMPTS: envSecurity.MAX_LOGIN_ATTEMPTS,
    ACCOUNT_LOCK_TIME: envSecurity.ACCOUNT_LOCK_TIME,

    // Password Requirements (consistent across environments)
    MIN_PASSWORD_LENGTH: 8,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SPECIAL_CHARS: true
  }
}
