/**
 * Security Event Types Enum
 * Used for logging and tracking security-related events
 */
export enum SecurityEventType {
  LOGIN_SUCCESS = "LOGIN_SUCCESS",
  LOGIN_FAILED = "LOGIN_FAILED",
  LOGIN_BLOCKED = "LOGIN_BLOCKED",
  TOKEN_REFRESH = "TOKEN_REFRESH",
  TOKEN_REFRESH_FAILED = "TOKEN_REFRESH_FAILED",
  LOGOUT = "LOGOUT",
  LOGOUT_ALL = "LOGOUT_ALL",
  PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED",
  PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED",
  SIGNUP_SUCCESS = "SIGNUP_SUCCESS",
  SIGNUP_FAILED = "SIGNUP_FAILED",
  ACCOUNT_LOCKED = "ACCOUNT_LOCKED",
  SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY",
  TOKEN_BLACKLISTED = "TOKEN_BLACKLISTED",
  SESSION_CREATED = "SESSION_CREATED",
  SESSION_TERMINATED = "SESSION_TERMINATED"
}

/**
 * Session Status Enum
 * Used to track the current state of user sessions
 */
export enum SessionStatus {
  ACTIVE = "ACTIVE",
  EXPIRED = "EXPIRED",
  TERMINATED = "TERMINATED",
  REVOKED = "REVOKED"
}

/**
 * Device Type Enum
 * Used to categorize different device types for sessions
 */
export enum DeviceType {
  DESKTOP = "DESKTOP",
  MOBILE = "MOBILE",
  TABLET = "TABLET",
  UNKNOWN = "UNKNOWN"
}

/**
 * Security Severity Levels
 * Used to categorize the severity of security events
 */
export enum SecuritySeverity {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL"
}

/**
 * Session Termination Reasons
 * Used to track how and why sessions were terminated
 */
export enum SessionTerminationReason {
  USER_LOGOUT = "USER_LOGOUT",
  ADMIN_REVOKED = "ADMIN_REVOKED",
  EXPIRED = "EXPIRED",
  SECURITY_REVOKED = "SECURITY_REVOKED",
  TOKEN_REFRESH = "TOKEN_REFRESH",
  PASSWORD_RESET = "PASSWORD_RESET",
  LOGOUT_ALL = "LOGOUT_ALL"
}

/**
 * User Role Enum
 * Used for role-based access control throughout the application
 */
export enum UserRole {
  USER = "USER",
  ADMIN = "ADMIN"
}
