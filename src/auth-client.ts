import crypto from 'crypto'
import mysql from 'mysql';
import { MySqlQuery } from './mysql-query';
import { IUserInfo } from './classes/user-info';
import { UserInfo, userInfo } from 'os';
import { UserIdentity } from './classes/user-identity';
import e from 'express';
import { ILoginRequest } from './classes/login-request';
import { generatePasswordHash, generateSalt, generateSessionToken } from './auth-crypto';
import { IdentityToken } from './classes/identity-token';

export class AuthClient {
  public dbname: string;
  public host: string;
  public user: string;
  public password: string;

  public pool: mysql.Pool | undefined;

  public readonly tableNames = {
    forgeryTokenStore: 'auth_forgery_token_store',
    userTable: 'account_user_info',
    passwordStore: 'auth_user_password_store',
    hashSaltStore: 'auth_hash_salt_store',
    userRoleStore: 'account_user_roles',
    sessionTokenStore: 'auth_session_token_store'
  }

  constructor({ dbname, host, user, password }: { dbname: string, host: string, user: string, password: string }) {
    this.dbname = dbname;
    this.host = host;
    this.user = user;
    this.password = password;
  }

  /// PUBLIC METHODS

  /**
   * Instruct the AuthClient to initiate connection with the database 
   */
  public async start() {
    const options: mysql.PoolConfig = {
      connectTimeout: 10,
      host: this.host,
      user: this.user,
      password: this.password,
      database: this.dbname,
      queryFormat: (query: string, values: any) => {
        if (!values) return query;
        return query.replace(/[@](\w+)/g, (txt, key) => {
          if (values.hasOwnProperty(key)) {
            return mysql.escape(values[key]);
          }
          return txt;
        })
      }
    }
    const pool = mysql.createPool(options);
    console.log('Connection established!');
    this.pool = pool;
  }

  /**
   * This method initiates a client connection to the REST API.
   * If a token is provided, the existing token will be removed from the database and a new one will be assigned
   * If a token is not provided, one is created and returned.
   * @param requestTokenFromHeaders (optional) Corresponds to the __requesttoken to be passed from each requests headers
   * @returns the string token
   */
  public async connect(requestTokenFromHeaders?: string): Promise<string> {
    const dbconn = await this.getConnection();

    console.log('initializeConnection called');

    if (requestTokenFromHeaders) {
      const qString = `DELETE FROM ${this.tableNames.forgeryTokenStore} WHERE [session_token]=@session_token`;

      const query = new MySqlQuery(qString, dbconn, { parameters: { session_token: requestTokenFromHeaders } });
      await query.executeNonQueryAsync();
    }

    const token = await new Promise<string>(resolve => {
      crypto.randomBytes(196, (err, buffer) => {
        return resolve(buffer.toString('base64'));
      });
    });
    console.log(token.length);

    const qString = `INSERT INTO ${this.tableNames.forgeryTokenStore} (session_token, date_created) VALUES (@session_token, @date_created)`;

    const query = new MySqlQuery(qString, dbconn, { parameters: { session_token: token, date_created: new Date() } });
    const result = await query.executeNonQueryAsync();
    dbconn.release();
    console.log(result);
    return token;
  }

  /**
   * Register a new user. Only database and injection protections are done beyond this point.
   * All data validation should be done prior to calling the register() method.
   * @param userInfo the user information to register
   * @returns The identity of the newly registered user
   */
  public async register(userInfo: IUserInfo) {
    if (!userInfo.email) {
      throw new Error('Email not provided in register method');
    }

    if (!userInfo.username) {
      throw new Error('Username not provided in register method');
    }

    if (!userInfo.password) {
      throw new Error('Password not provided in register method');
    }

    const dbconn = await this.getConnection();

    const isNewUser = this._checkDuplicateEmailUser(userInfo.email, userInfo.username, dbconn);
    if (isNewUser) {
      const user = await this._createNewUser(userInfo, dbconn);
      if (user && user.id) {
        const salt = await this._createUserSaltKey(user, dbconn);
        if (salt) {
          const passwordSave = await this._storeUserPassword(user.id, userInfo.password, salt, dbconn);
          if (passwordSave) {
            dbconn.release();
            return user;
          } else {
            dbconn.release();
            throw new Error('An error occurred (code 3)');
          }
        } else {
          dbconn.release();
          throw new Error('An error occured (code 2)');
        }
      } else {
        dbconn.release();
        throw new Error('An error occurred (code 1)');
      }
    } else {
      dbconn.release();
      throw new Error('Duplicate email or username provided');
    }
  }


  /**
   * Login a user. Only database and injection protections are done beyond this point.
   * All data validation should be done prior to calling the login() method.
   * @param loginRequest The login request to be attempted
   * @returns The identity of the user and session token or undefined if invalid login
   */
  public async login(loginRequest: ILoginRequest) {
    const dbconn = await this.getConnection();

    const user = await this._getUser(loginRequest.email, dbconn);
    if (user && user.id) {
      const salt: string = await this._getStoredSaltHash(user.id, dbconn);
      const passHash: string = await generatePasswordHash(loginRequest.password, salt);
      console.log(passHash);

      const qString = `SELECT COUNT(user_id) FROM ${this.tableNames.passwordStore} WHERE password=@password AND user_id=@user_id`;
      const query = new MySqlQuery(qString, dbconn, {
        parameters: {
          password: passHash,
          user_id: user.id,
        }
      });

      const userCount: number = await query.executeScalarAsync();
      if (userCount === 1) {
        user.getUserRoles(this.tableNames.userRoleStore, dbconn);

        await this._clearUserSessions(user.id, dbconn);
        const sessionPayload = await generateSessionToken();
        const sessionResult = await this._createUserSession(user.id, sessionPayload.selector, sessionPayload.token, dbconn);
        if (!sessionResult) {
          dbconn.release();
          return undefined;
        }

        return { user: user, sessionToken: sessionPayload.token + sessionPayload.selector };


      } else {
        dbconn.release();
        return undefined;
      }
    }
  }

  /**
   * Validate the request token of a request
   * @param requestToken The token gathered from the header of the request
   */
  public async validateRequest(requestToken: string) {
    const dbconn = await this.getConnection();
    const qString = `SELECT COUNT(id) FROM ${this.tableNames.forgeryTokenStore} WHERE session_token=@session_token`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        session_token: requestToken
      }
    });

    const count: number = await query.executeScalarAsync();
    dbconn.release();
    return count > 0;
  }

  public async validateSession(sessionToken: string) {
    if (sessionToken.length !== 512) {
      console.error('Session token invalid: Code 1');
      return undefined;
    }

    const splitIndex = 496;
    const validator: string = sessionToken.substr(0, splitIndex);
    const selector: string = sessionToken.substr(splitIndex);

    const dbconn = await this.getConnection();

    // Get the row id from the selector
    let qString = `SELECT id from ${this.tableNames.sessionTokenStore} WHERE selector=@selector`;
    let query = new MySqlQuery(qString, dbconn, {
      parameters: {
        selector: selector
      }
    });

    const rowId: number = await query.executeScalarAsync();
    if (!rowId) {
      dbconn.release();
      console.error('Session token invalid: Code 2');
    }

    qString = `SELECT * FROM ${this.tableNames.sessionTokenStore} WHERE id=@id`;
    query = new MySqlQuery(qString, dbconn, {
      parameters: {
        id: rowId
      }
    });

    const qResult = await query.executeQueryAsync();
    if (!qResult.results[0]) {
      dbconn.release();
      throw new Error('Session token invalid: Code 3');
    }
    const storedToken = new IdentityToken({
      date_created: qResult.results[0].date_created,
      id: qResult.results[0].id,
      selector: qResult.results[0].selector,
      user_id: qResult.results[0].user_id,
      validator: qResult.results[0].validator
    });

    let userId = 0;
    if (storedToken.validator === validator) {
      userId = storedToken.user_id;
    } else {
      dbconn.release();
      
    }

    const user = this._getUser(userId, dbconn);

  }



  /// PRIVATE METHODS

  private async getConnection() {
    return new Promise<mysql.PoolConnection>((resolve, reject) => {
      if (this.pool) {
        this.pool.getConnection((err, conn) => {
          if (err) return reject(err);
          return resolve(conn);
        });
      }
    });
  }

  private async _clearUserSessions(userId: number, dbconn: mysql.PoolConnection) {
    let qString = `DELETE FROM ${this.tableNames.sessionTokenStore} WHERE user_id=@user_id`
    let query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId
      }
    });

    const deleteResult = await query.executeNonQueryAsync();
    return true;
  }

  private async _createUserSession(userId: number, selector: string, validator: string, dbconn: mysql.PoolConnection) {
    const qString = `INSERT INTO ${this.tableNames.sessionTokenStore} (user_id, selector, validator, date_created) VALUES (@user_id, @selector, @validator, @date_created)`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId,
        selector: selector,
        validator: validator,
        date_created: new Date()
      }
    });

    const saveResult = await query.executeNonQueryAsync();
    if (saveResult.affectedRows === 1) {
      return true;
    } else {
      return false;
    }
  }

  private async _getStoredSaltHash(userId: number, dbconn: mysql.PoolConnection) {
    const qString = `SELECT hash_salt from ${this.tableNames.hashSaltStore} WHERE user_id=@user_id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId
      }
    });

    const saltString: string = await query.executeScalarAsync();
    return saltString;
  }

  private async _checkDuplicateEmailUser(email: string, username: string, dbconn: mysql.PoolConnection) {
    const qString = `SELECT COUNT(id) AS user_count FROM ${this.tableNames.userTable} WHERE email=@email OR username=@username`;
    const query = new MySqlQuery(qString, dbconn, { parameters: { email: email, username: username } });
    const results = await query.executeScalarAsync<number>();
    return results === 0;
  }

  private async _getUser(email: string, dbconn: mysql.PoolConnection): Promise<UserIdentity | undefined>
  private async _getUser(userId: number, dbconn: mysql.PoolConnection): Promise<UserIdentity | undefined>
  private async _getUser(arg: number | string, dbconn: mysql.PoolConnection) {
    const query = new MySqlQuery('', dbconn);
    if (typeof arg === 'number') {
      query.qString = `SELECT id, email, username, fname, lname FROM ${this.tableNames.userTable} WHERE id=@id`;
      query.parameters.id = arg;
    } else if (typeof arg === 'string') {
      query.qString = `SELECT id, email, username, fname, lname FROM ${this.tableNames.userTable} WHERE email=@email`;
      query.parameters.email = arg;
    } else {
      throw new Error('typeof arg should be number or string');
    }

    const rows = await query.executeQueryAsync();
    if (rows.results && rows.results.length > 0) {
      return new UserIdentity({
        id: rows.results[0].id,
        email: rows.results[0].email,
        lname: rows.results[0].lname,
        fname: rows.results[0].fname
      })
    }
    return undefined;
  }

  private async _createUserSaltKey(user: UserIdentity, dbconn: mysql.PoolConnection) {
    const salt: string = await generateSalt();
    const qString = `INSERT INTO ${this.tableNames.hashSaltStore} (user_id, hash_salt) VALUES (@user_id, @hash_salt)`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: user.id,
        hash_salt: salt
      }
    });

    const results = await query.executeNonQueryAsync();
    return results.affectedRows === 1 ? salt : undefined;
  }

  private async _storeUserPassword(userId: number, password: string, salt: string, dbconn: mysql.PoolConnection) {
    const passwordHash: string = await generatePasswordHash(password, salt);
    console.log('Password Length:', passwordHash.length);
    console.log('Salt Length:', salt.length);

    const qString = `INSERT INTO ${this.tableNames.passwordStore} (user_id, password) VALUES (@user_id, @password)`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId,
        password: passwordHash
      }
    });

    const result = await query.executeNonQueryAsync();

    return result.affectedRows === 1 ? true : false;
  }

  private async _createNewUser(userInfo: IUserInfo, dbconn: mysql.PoolConnection) {
    const qString = `INSERT INTO ${this.tableNames.userTable} (username, email, fname, lname, 
      address1, address2, country, state, city, zip, company_name, job_title, 
      date_created, phone, dob, email_verified) VALUES (@username, @email, @fname, @lname, 
        @address1, @address2, @country, @state, @city, @zip, @company_name, @job_title, 
        @date_created, @phone, @dob, @email_verified)`;

    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        username: userInfo.username,
        email: userInfo.email,
        fname: userInfo.fname,
        lname: userInfo.lname,
        address1: userInfo.address,
        address2: userInfo.address2,
        country: userInfo.country,
        state: userInfo.state,
        city: userInfo.city,
        zip: userInfo.zip,
        company_name: userInfo.company_name,
        job_title: userInfo.job_title,
        date_created: new Date(),
        phone: userInfo.phone,
        dob: userInfo.dob,
        email_verified: 0
      }
    });

    const qResult = await query.executeNonQueryAsync();
    const userId = qResult.insertId;

    return await this._getUser(userId, dbconn);
  }

}