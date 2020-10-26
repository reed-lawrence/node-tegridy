import crypto from 'crypto'
import mysql from 'mysql';
import { MySqlQuery } from './mysql-query';
import { IUserInfo } from './classes/user-info';
import { UserIdentity } from './classes/user-identity';
import { ILoginRequest } from './classes/login-request';
import { generatePasswordHash, generateSalt, generateSessionToken, randomBytes } from './auth-crypto';
import { IdentityToken } from './classes/identity-token';
import { ILoginResponse } from './classes/login-response';
import { IAuthClientOptions } from './classes/auth-client-options';
import { IPasswordResetPayload } from './classes/password-reset-payload';

export class AuthClient {
  
  constructor(init?: IAuthClientOptions) {
    if (init) {
      if (init.user) { this.user = init.user; }
      if (init.dbname) { this.dbname = init.dbname; }
      if (init.host) { this.host = init.host; }
      if (init.password) { this.password = init.password; }
      if (init.port) { this.port = init.port; }
      if (init.opts) {
        if (init.opts.concurrent_sessions) { this.concurrent_sessions = init.opts.concurrent_sessions; }
        if (init.opts.hash_iterations) { this.hash_iterations = init.opts.hash_iterations; }
      }
    }
  }

  public dbname: string = 'auth_server';
  public host: string = 'localhost';
  public user: string = 'root';
  public password: string = '';
  public port: number = 3306;

  public pool: mysql.Pool | undefined;

  public readonly tableNames = {
    forgeryTokenStore: 'auth_forgery_token_store',
    userTable: 'account_user_info',
    passwordStore: 'auth_user_password_store',
    hashSaltStore: 'auth_hash_salt_store',
    userRoleStore: 'account_user_roles',
    sessionTokenStore: 'auth_session_token_store',
    passResetKeyStore: 'auth_pass_reset_store'
  }

  /**
     * Number of times a password will be hashed via pbkdf2 cyrptography
     * (Default: 100)
     */
  private readonly hash_iterations: number = 100;

  /**
     * Number of concurrent sessions allowed to be open. The oldest session token 
     * will be removed when the session count exceeds the specified number.
     * (Default: unlimited)
     */
  private readonly concurrent_sessions: number | undefined;
  
  private readonly email_regex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

  /// PUBLIC METHODS

  /**
   * Instruct the AuthClient to initiate connection with the database 
   */
  public async Start() {
    const options: mysql.PoolConfig = {
      host: this.host,
      user: this.user,
      password: this.password,
      database: this.dbname,
      port: this.port,
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
  public async Connect(requestTokenFromHeaders?: string): Promise<string> {
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
  public async Register(userInfo: IUserInfo) {
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
  public async Login(sessionToken?: string, loginRequest?: Partial<ILoginRequest>): Promise<ILoginResponse | undefined> {
    const dbconn = await this.getConnection();

    /**
     * if a session token is supplied:
     *  - Attempt to validate the current session token
     *    - If session token is valid, update the token date and return the user
     */
    if (sessionToken) {
      const user = await this.ValidateSession(sessionToken, dbconn);
      if (user) {
        await this._updateUserSession(user.id, sessionToken, dbconn);
        await this._cleanUserSessions(user.id, dbconn);
        dbconn.release();
        return { user, sessionToken: sessionToken };
      }
    }

    /**
     * If a sessionToken was not provided or is not valid, we need to look for login credentials
     */
    if (loginRequest) {
      if (!loginRequest.email) {
        throw new Error('Email not provided');
      }

      if (!loginRequest.password) {
        throw new Error('Password not provided');
      }

      /**
       * Get the user credientials according to the email supplied.
       *  - If no email matching, return void
       *  - If email and password match, get and return user identity and new sessionToken
       */
      const user = await this._getUser(loginRequest.email, dbconn);
      if (user && user.id) {
        const salt: string = await this._getStoredSaltHash(user.id, dbconn);
        const passHash: string = await generatePasswordHash(loginRequest.password, salt, this.hash_iterations);
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
          await user.getUserRoles(this.tableNames.userRoleStore, dbconn);

          await this._cleanUserSessions(user.id, dbconn);
          const sessionPayload = await generateSessionToken();
          const sessionResult = await this._createUserSession(user.id, sessionPayload.selector, sessionPayload.token, dbconn);

          if (!sessionResult) {
            console.error('Unable to create a new sessionToken for the user');
            dbconn.release();
            return;
          }

          await this._cleanUserSessions(user.id, dbconn);
          dbconn.release();

          return { user, sessionToken: sessionPayload.token + sessionPayload.selector };

        } else {
          console.error('No matching password hash found for the login attempt');
          dbconn.release();
          return;
        }
      } else {
        console.error('No matching email found for the login attempt');
        dbconn.release();
        return;
      }
    } else {
      dbconn.release();
      throw new Error('No login request payload provided');
    }
  }

  /**
   * Validate the request token of a request
   * @param requestToken The token gathered from the header of the request
   */
  public async ValidateRequest(requestToken: string) {
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

  /**
   * Validate the current user session
   * @param sessionToken the session token to validate
   * @param dbconn (optional) MySQL connection to utilize. If none is supplied, one will be created.
   */
  public async ValidateSession(sessionToken: string, dbconn?: mysql.PoolConnection) {
    if (sessionToken.length !== 512) {
      console.error('Session token invalid: Code 1');
      return undefined;
    }

    const splitIndex = 496;
    const validator: string = sessionToken.substr(0, splitIndex);
    const selector: string = sessionToken.substr(splitIndex);

    if (!dbconn) {
      dbconn = await this.getConnection();
    }

    // Get the row id from the selector
    let qString = `SELECT id from ${this.tableNames.sessionTokenStore} WHERE selector=@selector`;
    let query = new MySqlQuery(qString, dbconn, {
      parameters: {
        selector: selector
      }
    });

    const rowId: number = parseInt(await query.executeScalarAsync(), 10);
    if (!rowId) {
      dbconn.release();
      console.error('Cannot find a matching row corresponding to the given token selector');
      return;
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
      console.error('No rows returned corresponding to the Id returned from the given token selector');
      return;
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
      console.error('User returned does not correspond to stored token user');
      return;
    }

    const user = await this._getUser(userId, dbconn);
    return user;
  }

  /**
   * Destroys the current user session
   * @param sessionToken the session token to destroy
   */
  public async Logout(sessionToken: string) {
    const dbconn = await this.getConnection();
    const user = await this.ValidateSession(sessionToken, dbconn);
    if (user) {
      const destroyResult: boolean = await this._destroyUserSession(user.id, sessionToken, dbconn);
      dbconn.release();

      if (destroyResult) {
        return true;
      } else {
        console.error('Unable to destroy user session');
        return false;
      }
    } else {
      dbconn.release();
      return false;
    }
  }

  public async CreatePasswordResetKey(email: string) {
    if (!this.email_regex.test(email)) {
      console.error('Supplied email is improperly formatted');
      return;
    }

    if (email.length > 60) {
      console.error('Email length must be shorter than 60 characters');
      return;
    }

    const dbconn = await this.getConnection();
    const user = await this._getUser(email, dbconn);
    if (!user) {
      console.error('No user matching supplied email');
      return;
    }

    const key = await this._createPasswordResetKey(email, dbconn);
    dbconn.release();
    return key ? key : undefined;
  }

  public async ResetPassword(payload: IPasswordResetPayload) {
    if (!payload) {
      console.error('No payload supplied');
      return;
    }
    if (!payload.email) {
      console.error('No email supplied');
      return;
    }
    if (!payload.password) {
      console.error('No password supplied');
      return;
    }
    if (!payload.secret) {
      console.error('No reset key supplied');
      return;
    }
    if (!this.email_regex.test(payload.email)) {
      console.error('Supplied email is improperly formatted');
      return;
    }
    if (payload.email.length > 60) {
      console.error('Email length must be shorter than 60 characters');
      return;
    }

    const dbconn = await this.getConnection();

    const resetResult = await this._resetPassword(payload, dbconn);
    dbconn.release();
    return resetResult;
  }

  public async GetAccountInfo(user: UserIdentity) {
    const dbconn = await this.getConnection();

    const userInfo = await this._getUserInfo(user, dbconn);

    dbconn.release();
    return userInfo;
  }


  /// PRIVATE METHODS

  private async getConnection() {
    return new Promise<mysql.PoolConnection>((resolve, reject) => {
      if (this.pool) {
        this.pool.getConnection((err, conn) => {
          if (err) return reject(err);
          return resolve(conn);
        });
      } else {
        return reject(new Error('Unable to connect to authentication server instance'));
      }
    });
  }

  private async _getUserInfo(user: UserIdentity, dbconn: mysql.PoolConnection): Promise<IUserInfo | undefined> {
    const qString = `SELECT * FROM ${this.tableNames.userTable} WHERE id=@id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        id: user.id
      }
    });

    const rows = await query.executeQueryAsync();
    if (rows.results && rows.results.length > 0) {
      return {
        username: rows.results[0].username,
        email: rows.results[0].email,
        email_verfified: rows.results[0].email_verfified,
        fname: rows.results[0].fname,
        lname: rows.results[0].lname,
        address: rows.results[0].address1,
        address2: rows.results[0].address2,
        country: rows.results[0].country,
        state: rows.results[0].state,
        city: rows.results[0].city,
        zip: rows.results[0].zip,
        company_name: rows.results[0].company_name,
        job_title: rows.results[0].job_title,
        date_created: rows.results[0].date_created,
        phone: rows.results[0].phone,
        dob: rows.results[0].dob,
        password: undefined
      }
    } else {
      return;
    }
  }

  private async _resetPassword(payload: IPasswordResetPayload, dbconn: mysql.PoolConnection) {

    // Get the count of non expired matching password reset keys
    let qString = `SELECT COUNT(id) FROM ${this.tableNames.passResetKeyStore} WHERE email=@email AND reset_key=@reset_key AND date_created > NOW() - 1;`;
    let query = new MySqlQuery(qString, dbconn, {
      parameters: {
        email: payload.email,
        reset_key: payload.secret
      }
    });

    const count = parseInt(await query.executeScalarAsync(), 10);
    if (count > 0) {

      // Get the corresponding user according to the supplied email
      const user = await this._getUser(payload.email, dbconn);
      if (user && user.id) {

        // Delete the existing password

        qString = `DELETE FROM ${this.tableNames.passwordStore} WHERE user_id=@user_id`;
        query = new MySqlQuery(qString, dbconn, {
          parameters: {
            user_id: user.id
          }
        });

        const passDelResult = await query.executeNonQueryAsync();
        if (!passDelResult.affectedRows) {
          console.error('Unable to delete password corresponding to the user specified');
          return false;
        }

        qString = `DELETE FROM ${this.tableNames.hashSaltStore} WHERE user_id=@user_id`;
        query = new MySqlQuery(qString, dbconn, {
          parameters: {
            user_id: user.id
          }
        });

        const hashDelResult = await query.executeNonQueryAsync();
        if (!hashDelResult.affectedRows) {
          console.error('Unable to delete the hash salt corresponding to the user specified');
          return false;
        }

        const salt = await generateSalt();
        const storeResult = await this._storeUserPassword(user.id, payload.password, salt, dbconn);

        if (storeResult) {
          qString = `DELETE FROM ${this.tableNames.passResetKeyStore} WHERE email=@email`;
          query = new MySqlQuery(qString, dbconn, {
            parameters: {
              email: payload.email
            }
          });

          const resetDelResult = await query.executeNonQueryAsync();

          if (!resetDelResult.affectedRows) {
            console.error('Unable to delete existing password reset keys');
          }

          return true;

        } else {
          console.error('Unable to save user password');
          return false;
        }


      } else {
        console.error('No matching user found corresponding to email');
        return false;
      }
    } else {
      console.error('No matching reset keys found');
      return false;
    }
  }

  private async _createPasswordResetKey(email: string, dbconn: mysql.PoolConnection) {
    const key = await randomBytes(64);
    const qString = `INSERT INTO ${this.tableNames.passResetKeyStore} (email, reset_key, date_created) VALUES (@email, @reset_key, @date_created)`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        email: email,
        reset_key: key,
        date_created: new Date()
      }
    });

    const result = await query.executeNonQueryAsync();
    if (result.affectedRows === 1) {
      return key;
    } else {
      console.error('Unable to insert key into database');
    }
  }

  private async _destroyUserSession(userId: number, sessionToken: string, dbconn: mysql.PoolConnection) {
    const splitIndex = 496;
    const validator: string = sessionToken.substr(0, splitIndex);
    const selector: string = sessionToken.substr(splitIndex);

    let qString = `DELETE FROM ${this.tableNames.sessionTokenStore} WHERE user_id=@user_id AND validator=@validator AND selector=@selector`;
    let query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId,
        validator: validator,
        selector: selector
      }
    });

    const deleteResult = await query.executeNonQueryAsync();

    // Ensure there are no matching sessions
    qString = `SELECT COUNT(id) FROM ${this.tableNames.sessionTokenStore} WHERE user_id=@user_id AND validator=@validator AND selector=@selector`;
    query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId,
        validator: validator,
        selector: selector
      }
    });

    const numrows: number = parseInt(await query.executeScalarAsync(), 10);
    if (numrows === 0) {
      return true;
    } else {
      return false;
    }
  }

  private async _cleanUserSessions(userId: number, dbconn: mysql.PoolConnection) {
    if (this.concurrent_sessions) {
      let qString = `SELECT COUNT(user_id) FROM ${this.tableNames.sessionTokenStore} WHERE user_id=@user_id`;
      let query = new MySqlQuery(qString, dbconn, {
        parameters: {
          user_id: userId
        }
      });
      const count: number = parseInt(await query.executeScalarAsync(), 10);
      if (count > this.concurrent_sessions) {
        const tokens = await this._getUserIdentityTokens(userId, dbconn);
        tokens.sort((a, b) => a.date_created < b.date_created ? 1 : a.date_created > b.date_created ? -1 : 0);

        const toRemove = new Array<IdentityToken>();
        for (let i = this.concurrent_sessions; i < tokens.length; i++) {
          toRemove.push(tokens[i]);
        }

        for (const token of toRemove) {
          qString = `DELETE FROM ${this.tableNames.sessionTokenStore} WHERE id=@id`;
          query = new MySqlQuery(qString, dbconn, {
            parameters: {
              id: token.id
            }
          });

          await query.executeNonQueryAsync();
        }
      }
    }
    return;
  }

  private async _getUserIdentityTokens(userId: number, dbconn: mysql.PoolConnection) {
    const tokenList = new Array<IdentityToken>();

    const qString = `SELECT * FROM ${this.tableNames.sessionTokenStore} WHERE user_id=@user_id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId
      }
    });

    const rows = await query.executeQueryAsync();
    if (rows.results && rows.results.length > 0) {
      for (const row of rows.results) {
        tokenList.push(new IdentityToken({
          date_created: row.date_created,
          id: row.id,
          selector: row.selector,
          user_id: row.user_id,
          validator: row.validator
        }));
      }
    }
    return tokenList;
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

  /**
   * Refreshes date_created property of the session token in the database
   */
  private async _updateUserSession(userId: number, sessionToken: string, dbconn: mysql.PoolConnection) {

    const splitIndex = 496;
    const validator: string = sessionToken.substr(0, splitIndex);
    const selector: string = sessionToken.substr(splitIndex);

    const qString = `UPDATE ${this.tableNames.sessionTokenStore} SET date_created=@date_created WHERE user_id=@user_id AND selector=@selector AND validator=@validator`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        selector: selector,
        validator: validator,
        date_created: new Date(),
        user_id: userId
      }
    });

    const result = await query.executeNonQueryAsync();
    if (result.affectedRows === 1) {
      return true;
    } else {
      console.error('Unable to update session date_created');
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
    } else {
      return undefined;
    }
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
    const passwordHash: string = await generatePasswordHash(password, salt, this.hash_iterations);
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