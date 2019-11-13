import crypto from 'crypto';

export async function generatePasswordHash(password: string, salt: string) {
  return new Promise<string>((resolve, reject) => {
    crypto.pbkdf2(password, Buffer.from(salt, 'base64'), 25000, 96, 'sha1', (err, key) => {
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

export async function generateSalt(): Promise<string> {
  return (await randomBytes(24)).toString('base64');
}

export async function generateSessionToken(): Promise<{ selector: string; token: string }> {
  const tokenLength = 372;
  const selectorLength = 12;

  const tokenBuffer = await randomBytes(tokenLength);
  const selectorBuffer = await randomBytes(selectorLength);

  const tokenStr = tokenBuffer.toString('base64').replace(/[\/]/g, '_').replace(/[+]/g, '-');
  const selectorStr = selectorBuffer.toString('base64').replace(/[\/]/g, '_').replace(/[+]/g, '-');
  return { selector: selectorStr, token: tokenStr };
}