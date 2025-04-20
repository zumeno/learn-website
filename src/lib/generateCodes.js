import crypto from 'crypto';

export function generateSecretKeyHash(secretKey) {
  return crypto.createHash('sha256')
    .update(String(secretKey))
    .digest();
}

export function generateCode(secretKey, input) {
  const iv = crypto.randomBytes(16);
  const data = `${input}:${secretKey}`;
 
  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    secretKey,
    iv
  );

  const encrypted = Buffer.concat([cipher.update(input, 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decryptCode(encryptedData, secretKey) {
  const [ivHex, ciphertext] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'hex')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export function generateVerificationURL(email_secret, email, password_secret, password, timestamp_secret, timestamp_time, attempt_timestamp_secret, attempt_timestamp) {
  const emailCode = generateCode(email_secret, email);
  const passwordCode = generateCode(password_secret, password);
  const timestamp_code = generateCode(timestamp_secret, timestamp_time);
  const attempt_timestamp_code = generateCode(attempt_timestamp_secret, attempt_timestamp);

  return `/verify?email=${emailCode}&password=${passwordCode}&timestamp=${timestamp_code}&attemptTimestamp=${attempt_timestamp_code}`;
}

export function decryptVerificationURL(encryptedURL, email_secret, password_secret, timestamp_secret, attempt_timestamp_secret) {
    try {
      const urlObj = new URL(encryptedURL);
      const params = urlObj.searchParams;

      const emailCode = params.get('email');
      const passwordCode = params.get('password');
      const timestampCode = params.get('timestamp');
      const attemptTimestampCode = params.get('attemptTimestamp');

      if (!emailCode || !passwordCode || !timestampCode || !attemptTimestampCode) {
        return null; 
      }

      const decryptedEmail = decryptCode(emailCode, email_secret);
      const decryptedPassword = decryptCode(passwordCode, password_secret);
      const decryptedTimestamp = decryptCode(timestampCode, timestamp_secret);
      const decryptedAttemptTimestamp = decryptCode(attemptTimestampCode, attempt_timestamp_secret);

      if (!decryptedEmail || !decryptedPassword || !decryptedTimestamp || !decryptedAttemptTimestamp) {
        return null; 
      }

      return {
        email: decryptedEmail,
        password: decryptedPassword,
        timestamp: decryptedTimestamp,
        attemptTimestamp: decryptedAttemptTimestamp,
      };
    } catch (error) {
        console.error('URL decryption failed:', error);
        return null;
    }
}

export function generateVerificationCode(verification_secret, email, password, current_time) {
  const hmac = crypto.createHmac('sha256', verification_secret)
                    .update(`${email}:${password}:${current_time}`)
                    .digest('hex');

   const code = parseInt(hmac.substring(0, 6), 16) % 1_000_000;
  return String(code).padStart(6, '0');
}
