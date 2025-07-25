import { Injectable, NestMiddleware } from "@nestjs/common"
import { Request, Response, NextFunction } from "express"

@Injectable()
export class SecurityHeadersMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Prevent clickjacking attacks
    res.setHeader("X-Frame-Options", "DENY")

    // Prevent MIME type sniffing
    res.setHeader("X-Content-Type-Options", "nosniff")

    // Enable XSS protection
    res.setHeader("X-XSS-Protection", "1; mode=block")

    // Referrer Policy - control how much referrer information should be included
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin")

    // Feature Policy - control which web platform features can be used
    res.setHeader(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()"
    )

    // Content Security Policy (CSP) - prevent XSS and other code injection attacks
    const cspDirectives = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval'", // Allow eval for development, remove in production
      "style-src 'self' 'unsafe-inline'", // Allow inline styles
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join("; ")

    res.setHeader("Content-Security-Policy", cspDirectives)

    // HSTS (HTTP Strict Transport Security) - enforce HTTPS
    if (req.secure || req.get("x-forwarded-proto") === "https") {
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    }

    // Cross-Origin Resource Policy
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin")

    // Cross-Origin Embedder Policy
    res.setHeader("Cross-Origin-Embedder-Policy", "require-corp")

    // Cross-Origin Opener Policy
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin")

    // Remove server information
    res.removeHeader("X-Powered-By")
    res.removeHeader("Server")

    // Add custom security headers
    res.setHeader("X-API-Version", "1.0.0")
    res.setHeader("X-Security-Policy", "enabled")

    // Cache control for sensitive endpoints
    if (req.path.includes("/auth/") || req.path.includes("/user/")) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private")
      res.setHeader("Pragma", "no-cache")
      res.setHeader("Expires", "0")
    }

    next()
  }
}
