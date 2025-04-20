import nodemailer from 'nodemailer';
import { generateCode, generateVerificationCode } from "./generateCodes.js";

export async function sendVerificationEmail(emailPool, verification_secret, product_name, recipientEmail, password, current_time) {
  if (emailPool.length === 0) {
    throw new Error("No email accounts configured");
  }
  
  const verificationCode = generateVerificationCode(verification_secret, recipientEmail, password, current_time);
  
  let lastError = null;
  for (const account of emailPool) {
    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: account.address,
          pass: account.password
        }
      });
      
      await transporter.sendMail({
        from: `${product_name} <${account.address}>`,
        to: recipientEmail,
        subject: `Verification for ${product_name}`,
        html: `
          <p>Thank you for registering for ${product_name}</p>
          <p>Your ${product_name} verification code is: <strong>${verificationCode}</strong></p>
        `
      });
      
      return { success: true, verificationCode };
    } catch (error) {
      lastError = error;
    }
  }
  
  throw lastError || new Error("Failed to send verification email after all attempts");
}
