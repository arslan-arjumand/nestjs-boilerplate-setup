import { Injectable } from "@nestjs/common"
import * as nodemailer from "nodemailer"
import config from "@/config"

const { EMAIL, HOST, PORT, PASSWORD } = config.MAIL

@Injectable()
export class EmailService {
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
  }

  /**
   * Sends an email to the specified user.
   * @param {string} to - The email address of the recipient.
   * @param {string} subject - The subject of the email.
   * @param {string} text - The content of the email.
   * @returns {Promise<nodemailer.SentMessageInfo>} - A promise that resolves to the information about the sent email.
   */
  async sendEmail(to: string, subject: string, text: string): Promise<nodemailer.SentMessageInfo> {
    const mailOptions = {
      from: `"Backend Application" <${EMAIL}>`,
      to: to,
      subject: subject,
      text: text
    }

    const info = await this.transporter.sendMail(mailOptions)

    return info
  }
}
