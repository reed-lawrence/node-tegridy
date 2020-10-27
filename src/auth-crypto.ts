import crypto from 'crypto';

export async function generatePasswordHash(password: string, salt: string, iterations: number) {
  return new Promise<string>((resolve, reject) => {
    crypto.pbkdf2(password, Buffer.from(salt, 'base64'), iterations, 96, 'sha1', (err, key) => {
      if (err) {
        return reject(err);
      }

      return resolve(key.toString('base64'));
    });
  });
}

export async function randomBytes(length: number) {
  return new Promise<Buffer>((resolve, reject) => {
    crypto.randomBytes(length, (err, buffer) => {
      if (err) { return reject(err); }
      return resolve(buffer);
    })
  });
}

export async function randomChars(length: number) {
  const buffer = await randomBytes(length);
  return buffer.toString('base64').replace(/[\/]/g, '_').replace(/[+]/g, '-');
}

export async function generateSalt(): Promise<string> {
  return await randomChars(24);
}

export async function generateSessionToken(): Promise<{ selector: string; token: string }> {
  const tokenLength = 372;
  const selectorLength = 12;

  const tokenStr = await randomChars(tokenLength);
  const selectorStr = await randomChars(selectorLength);
  return { selector: selectorStr, token: tokenStr };
}