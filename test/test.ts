import { describe } from 'mocha';
import assert from 'assert';
import { AuthClient } from '../src/auth-client';
import { generatePasswordHash, generateRequestToken, generateSalt, generateSessionToken, randomChars } from '../src/auth-crypto';

describe('Crypto', () => {

  describe('Buffer Functions', () => {
    it('Buffer.from() should parse to byte array', async () => {
      const expected = [141, 10, 236, 171, 30, 152, 204, 64, 59, 173, 66, 37, 229, 12, 86, 137, 191, 39, 67, 239, 157, 48, 118, 224];

      const bufferString = 'jQrsqx6YzEA7rUIl5QxWib8nQ++dMHbg';
      const buffer = Buffer.from(bufferString, 'base64');

      const actual: number[] = [];
      buffer.forEach(byte => actual.push(byte));
      assert.strictEqual(expected.length, actual.length, 'Buffer lengths are not equal');
      for (let i = 0; i < expected.length; i++) {
        assert.strictEqual(expected[i], actual[i], `value at ${i} are not equal`);
      }
    });
  });

  describe('String Generation', () => {
    it('Random string lengths should be as input', async () => {
      // Arrange
      const expectedLength = 64;

      // Act
      const randomString = await randomChars(expectedLength);

      // Assert
      assert.strictEqual(randomString.length, expectedLength);
    });

    it('Random strings should not contain / or +', async () => {
      for (let i = 0; i < 1000; i++) {
        const str = await randomChars(100);
        assert.strictEqual(str.indexOf('/'), -1, 'Selector contains /');
        assert.strictEqual(str.indexOf('/'), -1, 'Token contains /');
      }
    });
  });

  describe('Hash Functions', () => {
    it('Password hash should produce correct hash', async () => {
      // Arrange
      const saltStr = 'jQrsqx6YzEA7rUIl5QxWib8nQ++dMHbg';
      const password = '123456789';
      const expectedHash = 'c89KCtUBxMiDi+5nJeX8DduiE6/+J6sNIq7deca9AlHSTehIYrN8cg2yg0z40oc/UJEujlx1IuWxeInnxEOg56JSfDYlMcIIHQUlSu2LyZkS9vLX1J48RKlik04rPc6z';
      const expectedLength = 128;

      // Act
      const actualHash = await generatePasswordHash(password, saltStr, 25000);

      // Assert
      assert.strictEqual(actualHash, expectedHash, 'Password hashes are not equal');
      assert.strictEqual(actualHash.length, expectedLength, 'Password hash length is not as expected');

    });

    it('Generated salt should be 32 characters long', async () => {
      assert.strictEqual((await generateSalt()).length, 32);
    });

    it('Generated reqest token should be 264 characters long', async () => {
      assert.strictEqual((await generateRequestToken()).length, 264);
    });

    it('Generated session token should be 512 characters long', async () => {
      const session = await generateSessionToken();
      assert.strictEqual(session.selector.length + session.token.length, 512);
    });

    it('Session Token should not contain + or /', async () => {
      // Perform multiple times for better coverage
      for (let i = 0; i < 1000; i++) {
        const payload = await generateSessionToken();
        assert.strictEqual(payload.selector.indexOf('/'), -1, 'Selector contains /');
        assert.strictEqual(payload.token.indexOf('/'), -1, 'Token contains /');
        assert.strictEqual(payload.selector.indexOf('+'), -1, 'Selector contains +');
        assert.strictEqual(payload.token.indexOf('+'), -1, 'Token contains +');
      }
    });

    it('Request Token should not contain + or /', async () => {
      // Perform multiple times for better coverage
      for (let i = 0; i < 1000; i++) {
        const str = await generateRequestToken();
        assert.strictEqual(str.indexOf('/'), -1, 'Selector contains /');
        assert.strictEqual(str.indexOf('/'), -1, 'Token contains /');
      }
    });

    it('Password hash-speed benchmark', async () => {
      // Arrange
      const saltStr = 'jQrsqx6YzEA7rUIl5QxWib8nQ++dMHbg';
      const password = '123456789';
      const expectedHash = 'c89KCtUBxMiDi+5nJeX8DduiE6/+J6sNIq7deca9AlHSTehIYrN8cg2yg0z40oc/UJEujlx1IuWxeInnxEOg56JSfDYlMcIIHQUlSu2LyZkS9vLX1J48RKlik04rPc6z';
      const expectedLength = 128;

      // Act
      const actualHash = await generatePasswordHash(password, saltStr, 25000);

      // Assert
      // None, purely for speed purposes

    });
  });

  describe('Hash Benchmarks', () => {

    it('1 iteration', async () => {
      // Arrange
      const iterations = 1;
      const saltStr = 'jQrsqx6YzEA7rUIl5QxWib8nQ++dMHbg';
      const password = '123456789';

      // Act
      const actualHash = await generatePasswordHash(password, saltStr, iterations);
    });

    it('100 iteration', async () => {
      // Arrange
      const iterations = 100;
      const saltStr = 'jQrsqx6YzEA7rUIl5QxWib8nQ++dMHbg';
      const password = '123456789';

      // Act
      const actualHash = await generatePasswordHash(password, saltStr, iterations);
    });

    it('1,000 iterations', async () => {
      // Arrange
      const iterations = 1000;
      const saltStr = 'jQrsqx6YzEA7rUIl5QxWib8nQ++dMHbg';
      const password = '123456789';

      // Act
      const actualHash = await generatePasswordHash(password, saltStr, iterations);
    });

    it('10,000 iterations', async () => {
      // Arrange
      const iterations = 10000;
      const saltStr = 'jQrsqx6YzEA7rUIl5QxWib8nQ++dMHbg';
      const password = '123456789';

      // Act
      const actualHash = await generatePasswordHash(password, saltStr, iterations);
    });

    it('100,000 iterations', async () => {
      // Arrange
      const iterations = 100000;
      const saltStr = 'jQrsqx6YzEA7rUIl5QxWib8nQ++dMHbg';
      const password = '123456789';

      // Act
      const actualHash = await generatePasswordHash(password, saltStr, iterations);
    });

  });

});