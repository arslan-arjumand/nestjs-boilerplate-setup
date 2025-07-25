import { Injectable, Logger } from "@nestjs/common"
import * as nodemailer from "nodemailer"
import config from "@/config"

const { EMAIL, HOST, PORT, PASSWORD } = config.MAIL

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name)
  private transporter: nodemailer.Transporter

  /**
   * Represents an EmailService that handles sending emails.
   */
  constructor() {
    /**
     * Creates a nodemailer transport object with the provided configuration.
     * @type {Transporter}
     */
    this.transporter = nodemailer.createTransport({
      host: HOST,
      port: Number(PORT),
      secure: false,
      auth: {
        user: EMAIL,
        pass: PASSWORD
      }
    })

    this.logger.log(`Email service initialized with host: ${HOST}:${PORT}`)
  }

  /**
   * Sends an email to the specified user.
   * @param {string} to - The email address of the recipient.
   * @param {string} subject - The subject of the email.
   * @param {string} text - The content of the email.
   * @returns {Promise<nodemailer.SentMessageInfo>} - A promise that resolves to the information about the sent email.
   */
  async sendEmail(to: string, subject: string, text: string): Promise<nodemailer.SentMessageInfo> {
    try {
      this.logger.log(`Sending email to: ${to} | Subject: "${subject}"`)

      const mailOptions = {
        from: `"Backend Application" <${EMAIL}>`,
        to: to,
        subject: subject,
        text: text
      }

      const info = await this.transporter.sendMail(mailOptions)

      this.logger.log(`Email sent successfully to ${to} | Message ID: ${info.messageId}`)
      return info
    } catch (error) {
      this.logger.error(`Failed to send email to ${to}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Sends email verification email to the specified user.
   * @param {string} to - The email address of the recipient.
   * @param {string} username - The username of the user.
   * @param {string} verificationToken - The verification token.
   * @param {string} frontendBaseUrl - The base URL of the frontend application.
   * @returns {Promise<nodemailer.SentMessageInfo>} - A promise that resolves to the information about the sent email.
   */
  async sendVerificationEmail(
    to: string,
    username: string,
    verificationToken: string,
    frontendBaseUrl: string = "http://localhost:3000"
  ): Promise<nodemailer.SentMessageInfo> {
    const verificationUrl = `${frontendBaseUrl}/verify-email?token=${verificationToken}`

    const subject = "Verify Your Email Address"
    const text = `
Hello ${username},

Welcome to our platform! To complete your registration, please verify your email address by clicking the link below:

${verificationUrl}

This verification link will expire in 24 hours for security reasons.

If you didn't create an account with us, please ignore this email.

Best regards,
The Backend Application Team
    `.trim()

    this.logger.log(`Sending verification email to: ${to} | Username: ${username}`)
    return this.sendEmail(to, subject, text)
  }

  /**
   * Sends a resend verification email to the specified user.
   * @param {string} to - The email address of the recipient.
   * @param {string} username - The username of the user.
   * @param {string} verificationToken - The verification token.
   * @param {string} frontendBaseUrl - The base URL of the frontend application.
   * @returns {Promise<nodemailer.SentMessageInfo>} - A promise that resolves to the information about the sent email.
   */
  async sendResendVerificationEmail(
    to: string,
    username: string,
    verificationToken: string,
    frontendBaseUrl: string = "http://localhost:3000"
  ): Promise<nodemailer.SentMessageInfo> {
    const verificationUrl = `${frontendBaseUrl}/verify-email?token=${verificationToken}`

    const subject = "Email Verification - Resent"
    const text = `
Hello ${username},

You requested to resend your email verification link. Please verify your email address by clicking the link below:

${verificationUrl}

This verification link will expire in 24 hours for security reasons.

If you didn't request this email, please ignore it.

Best regards,
The Backend Application Team
    `.trim()

    this.logger.log(`Sending resend verification email to: ${to} | Username: ${username}`)
    return this.sendEmail(to, subject, text)
  }
}
