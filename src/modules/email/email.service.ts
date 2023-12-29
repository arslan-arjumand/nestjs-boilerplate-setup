import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import Configuration from 'config/index';

const { MAIL } = Configuration();

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  /**
   * Initialize the email service with credentials
   */
  constructor() {
    this.transporter = nodemailer.createTransport({
      service: MAIL.SERVER,
      host: MAIL.HOST,
      port: MAIL.PORT,
      secure: false,
      auth: {
        user: MAIL.EMAIL,
        pass: MAIL.PASSWORD,
      },
    });
  }

  /**
   * Method to send emails to the specific user
   */
  async sendEmail(to: string, subject: string, text: string) {
    const mailOptions = {
      from: `"Dashboard" <${MAIL.EMAIL}>`,
      to: to,
      subject: subject,
      text: text,
    };

    const info = await this.transporter.sendMail(mailOptions);

    return info;
  }
}
