import { createPool, escape, Pool, PoolConfig, PoolConnection } from 'mysql';

import {
  generatePasswordHash, generateRequestToken, generateSalt, generateSessionToken, randomChars
} from './auth-crypto';
import { IAuthClientOptions } from './classes/auth-client-options';
import { IdentityToken } from './classes/identity-token';
import { ILoginRequest } from './classes/login-request';
import { ILoginResponse } from './classes/login-response';
import { IQueryOptions, MySqlQuery } from '@reed-lawrence/mysql-query';
import { IPasswordResetPayload } from './classes/password-reset-payload';
import { UserIdentity } from './classes/user-identity';
import { IUserInfo } from './classes/user-info';
import { IUserUpdatePayload } from './classes/user-update-payload';

export class AuthClient {

  /**
   * The AuthClient class that serves as the service provider for Tegridy
   * @param dbconfig the MySql Connection Pool options
   * @param options (Optional) Specify parameters 
   */
  constructor(dbconfig: PoolConfig, options?: IAuthClientOptions) {
    dbconfig.queryFormat = (query: string, values: any) => {
      if (!values) return query;
      return query.replace(/[@](\w+)/g, (txt, key) => {
        if (values.hasOwnProperty(key)) {
          return escape(values[key]);
        }
        return txt;
      });
    };

    this.pool = createPool(dbconfig)
    if (options) {
      if (options.concurrent_sessions) { this.concurrent_sessions = options.concurrent_sessions; }
      if (options.hash_iterations) { this.hash_iterations = options.hash_iterations; }
      if (options.unique_user_fields) { this.unique_fields = options.unique_user_fields; }
    }
  }

  public readonly tableNames = {
    emailVerifications: 'auth_email_verifications',
    forgeryTokenStore: 'auth_forgery_tokens',
    hashSaltStore: 'auth_hash_salts',
    passResetKeyStore: 'auth_password_reset_requests',
    passwordStore: 'auth_passwords',
    roles: 'auth_roles',
    sessionTokenStore: 'auth_session_tokens',
    userRoleStore: 'auth_user_roles',
    userTable: 'auth_users',
  }

  public pool: Pool;

  /**
   * Number of times a password will be hashed via pbkdf2 cyrptography
   * (Default: 100)
   */
  private readonly hash_iterations: number = 100;

  /**
   * Number of concurrent sessions allowed to be open for a user. The oldest session token 
   * will be removed when the session count exceeds the specified number.
   * (Default: unlimited)
   */
  private readonly concurrent_sessions: number | undefined;

  private readonly unique_fields: (keyof IUserInfo)[] = ['email'];

  public readonly email_regex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

  private async getConnection() {
    return new Promise<PoolConnection>((resolve, reject) => {
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

  /// PUBLIC METHODS

  // #region TOKEN MANAGEMENT

  /**
   * This method initiates a client connection to the REST API.
   * If a token is provided, the existing token will be removed from the database and a new one will be assigned
   * If a token is not provided, one is created and returned.
   * @param requestTokenFromHeaders (optional) Corresponds to the __requesttoken to be passed from each requests headers
   * @returns the string token
   */
  public async RequestForgeryToken(requestTokenFromHeaders?: string): Promise<string> {
    const dbconn = await this.getConnection();

    try {

      if (requestTokenFromHeaders) {
        const qString = `DELETE FROM ${this.tableNames.forgeryTokenStore} WHERE session_token = @session_token`;

        const query = new MySqlQuery(qString, dbconn, {
          parameters: {
            session_token: requestTokenFromHeaders
          }
        });
        await query.executeNonQuery();
      }

      const token = await generateRequestToken();

      const qString = `INSERT INTO ${this.tableNames.forgeryTokenStore} (session_token, date_created) VALUES ( @session_token , @date_created)`;

      const query = new MySqlQuery(qString, dbconn, {
        parameters: {
          session_token: token,
          date_created: new Date()
        }
      });
      const result = await query.executeNonQuery();

      dbconn.release();

      return token;

    } catch (err) {

      dbconn.release();
      throw err;

    }
  }

  /**
   * Validate the request token of a request
   * @param requestToken The token gathered from the header of the request
   */
  public async ValidateRequest(requestToken: string) {
    const dbconn = await this.getConnection();

    try {

      const qString = `SELECT COUNT(id) FROM ${this.tableNames.forgeryTokenStore} WHERE session_token=@session_token`;
      const query = new MySqlQuery(qString, dbconn, {
        parameters: {
          session_token: requestToken
        }
      });

      const count: number = await query.executeScalar();
      dbconn.release();
      return count > 0;

    } catch (error) {

      dbconn.release();
      throw error;

    }

  }

  /**
   * Validate the current user session
   * @param sessionToken the session token to validate
   * @param dbconn (optional) MySQL connection to utilize. If none is supplied, one will be created.
   */
  public async ValidateSession(sessionToken: string, dbconn?: PoolConnection) {
    if (!dbconn) {
      dbconn = await this.getConnection();
    }

    try {

      if (sessionToken.length !== 512) {
        throw new Error('Session token invalid: Code 1');
      }

      const splitIndex = 496;
      const validator: string = sessionToken.substr(0, splitIndex);
      const selector: string = sessionToken.substr(splitIndex);

      // Get the row id from the selector
      let qString = `SELECT id from ${this.tableNames.sessionTokenStore} WHERE selector=@selector`;
      let query = new MySqlQuery(qString, dbconn, {
        parameters: {
          selector: selector
        }
      });

      const rowId: number = parseInt(await query.executeScalar(), 10);
      if (!rowId) {
        dbconn.release();
        throw new Error('Cannot find a matching row corresponding to the given token selector');
      }

      qString = `SELECT * FROM ${this.tableNames.sessionTokenStore} WHERE id=@id`;
      query = new MySqlQuery(qString, dbconn, {
        parameters: {
          id: rowId
        }
      });

      const qResult = await query.executeQuery();
      if (!qResult.results[0]) {
        dbconn.release();
        throw new Error('No rows returned corresponding to the Id returned from the given token selector');
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
        throw new Error('User returned does not correspond to stored token user');
      }

      const user = await this._getUser(userId, dbconn);
      return user;

    } catch (error) {

      dbconn.release();
      throw error;

    }

  }

  // #endregion

  // #region SESSION MANAGEMENT

  /**
   * Login a user. Only database and injection protections are done beyond this point.
   * All data validation should be done prior to calling the login() method.
   * @param loginRequest The login request to be attempted
   * @returns The identity of the user and session token or undefined if invalid login
   */
  public async Login(sessionToken?: string, loginRequest?: Partial<ILoginRequest>): Promise<ILoginResponse | undefined> {
    const dbconn = await this.getConnection();

    try {
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

          const userCount: number = await query.executeScalar();
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
    } catch (error) {

      dbconn.release();
      throw error;

    }
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

  // #endregion

  // #region USER MANAGEMENT

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

    try {

      for (const field of this.unique_fields) {
        if (field === 'email') {
          if (!await this._isUniqueEmail(userInfo.email, dbconn)) {
            throw new Error('Duplicate email provided');
          }
        }

        if (field === 'username') {
          if (!await this._isUniqueUsername(userInfo.username, dbconn)) {
            throw new Error('Duplicate email provided');
          }
        }
      }

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

    } catch (error) {

      dbconn.release();
      throw error;

    }
  }

  /**
   * Get the full account info related to the User
   * @param arg UserIdentity or User Id in string form
   */
  public async GetAccountInfo(userId: number) {
    if (typeof userId !== 'number') {
      throw new Error('User Id must be numeric type');
    }

    if (userId > 0) {
      const dbconn = await this.getConnection();

      try {

        const userInfo = await this._getUserInfo(userId, dbconn);
        dbconn.release();
        return userInfo;

      } catch (error) {

        dbconn.release();
        throw error;

      }
    } else {
      throw new Error('Invalid user.id');
    }
  }

  /**
   * Update the information associated with the user.
   * To update the Email, Username, Password, or Email Verification, use the respective method
   * @param userId 
   * @param userInfo 
   */
  public async UpdateAccountInfo(userId: number, userInfo: IUserUpdatePayload) {

    if (!userInfo) {
      throw new Error('No userInfo supplied');
    }

    const dbconn = await this.getConnection();

    try {

      const user = await this._updateUser(userId, userInfo, dbconn);
      dbconn.release();
      return user;

    } catch (error) {

      dbconn.release();
      throw error;

    }
  }

  /**
   * Method that checks for uniqueness and updates the username as desired
   * @param userId 
   * @param username 
   */
  public async UpdateUsername(userId: number, username: string) {
    if (!userId || userId <= 0) {
      throw new Error('Invalid user id');
    }

    if (!username) {
      throw new Error('Invalid username');
    }

    const dbconn = await this.getConnection();

    try {
      if (this.unique_fields.indexOf('username') && !(await this._isUniqueUsername(username, dbconn))) {
        throw new Error('Username is not unique');
      }

      const user = this._updateUsername(userId, username, dbconn);
      dbconn.release();
      return user;

    }
    catch (error) {
      dbconn.release();
      throw error;
    }
  }

  // #endregion

  // #region PASSWORD

  public async RequestPasswordReset(email: string) {
    if (!email) {
      throw new Error('No email supplied');
    }

    if (!this.email_regex.test(email)) {
      throw new Error('Supplied email is improperly formatted');
    }

    if (email.length > 60) {
      throw new Error('Email length must be shorter than 60 characters');
    }

    const dbconn = await this.getConnection();
    try {

      const user = await this._getUser(email, dbconn);
      if (!user) {
        throw new Error('No user matching supplied email');
      }

      const key = await this._createPasswordResetKey(email, dbconn);

      dbconn.release();
      return key;

    } catch (error) {

      dbconn.release();
      throw error;

    }
  }

  public async UpdatePassword(payload: IPasswordResetPayload) {
    if (!payload) {
      throw new Error('No payload supplied');
    }
    if (!payload.email) {
      throw new Error('No email supplied');
    }
    if (!payload.password) {
      throw new Error('No password supplied');
    }
    if (!payload.secret) {
      throw new Error('No reset key supplied');
    }
    if (!this.email_regex.test(payload.email)) {
      throw new Error('Supplied email is improperly formatted');
    }
    if (payload.email.length > 60) {
      throw new Error('Email length must be shorter than 60 characters');
    }

    const dbconn = await this.getConnection();

    try {

      const result = await this._updatePassword(payload, dbconn);
      dbconn.release();
      return result;

    } catch (error) {

      dbconn.release();
      throw error;

    }
  }

  // #endregion

  // #region EMAIL

  /**
   * Method that creates and stores the key responsible for verifying an email
   * @param userId  
   * @param email 
   * @returns the verification token to email to a user
   */
  public async RequestEmailVerification(userId: number, email: string) {
    if (!userId || userId <= 0) {
      throw new Error('Invalid user id');
    }

    if (!email) {
      throw new Error('Invalid email');
    }

    const dbconn = await this.getConnection();

    try {

      const result = await this._createEmailVerificationKey(userId, email, dbconn);
      dbconn.release();
      return result;

    } catch (error) {

      dbconn.release();
      throw error;

    }
  }

  /**
   * Method that checks the email for uniqueness and updates the email as desired
   * @param userId 
   * @param email 
   */
  public async UpdateEmail(userId: number, email: string) {
    if (!userId || userId <= 0) {
      throw new Error('Invalid user id');
    }

    if (!email || !this.email_regex.test(email)) {
      throw new Error('Invalid email');
    }

    const dbconn = await this.getConnection();

    try {

      const user = await this._updateEmail(userId, email, dbconn);
      dbconn.release();
      return user;

    } catch (error) {
      dbconn.release();
      throw error;
    }

  }

  /**
   * Method that verifies the email associted to the user given the specified token key and email
   * @param email 
   * @param key 
   */
  public async VerifyEmail(email: string, key: string) {

    if (!email) {
      throw new Error('Invalid email');
    }

    if (!key) {
      throw new Error('Invalid validation token');
    }

    const dbconn = await this.getConnection();

    try {

      const user = await this._getUser(email, dbconn);
      const result = await this._verifyEmail(user.id, email, key, dbconn);
      dbconn.release();
      return result;

    } catch (error) {
      dbconn.release();
      throw error;
    }
  }

  //#endregion

  /// PRIVATE METHODS

  // #region TOKEN/SESSION MANAGEMENT

  private async _destroyUserSession(userId: number, sessionToken: string, dbconn: PoolConnection) {
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

    const deleteResult = await query.executeNonQuery();

    // Ensure there are no matching sessions
    qString = `SELECT COUNT(id) FROM ${this.tableNames.sessionTokenStore} WHERE user_id=@user_id AND validator=@validator AND selector=@selector`;
    query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId,
        validator: validator,
        selector: selector
      }
    });

    const numrows: number = parseInt(await query.executeScalar(), 10);
    if (numrows === 0) {
      return true;
    } else {
      return false;
    }
  }

  private async _cleanUserSessions(userId: number, dbconn: PoolConnection) {
    if (this.concurrent_sessions) {
      let qString = `SELECT COUNT(user_id) FROM ${this.tableNames.sessionTokenStore} WHERE user_id=@user_id`;
      let query = new MySqlQuery(qString, dbconn, {
        parameters: {
          user_id: userId
        }
      });
      const count: number = parseInt(await query.executeScalar(), 10);
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

          await query.executeNonQuery();
        }
      }
    }
    return;
  }

  private async _getUserIdentityTokens(userId: number, dbconn: PoolConnection) {
    const tokenList = new Array<IdentityToken>();

    const qString = `SELECT * FROM ${this.tableNames.sessionTokenStore} WHERE user_id=@user_id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId
      }
    });

    const rows = await query.executeQuery();
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

  private async _createUserSession(userId: number, selector: string, validator: string, dbconn: PoolConnection) {
    const qString = `INSERT INTO ${this.tableNames.sessionTokenStore} (user_id, selector, validator, date_created) VALUES (@user_id, @selector, @validator, @date_created)`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId,
        selector: selector,
        validator: validator,
        date_created: new Date()
      }
    });

    const saveResult = await query.executeNonQuery();
    if (saveResult.affectedRows === 1) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * Refreshes date_created property of the session token in the database
   */
  private async _updateUserSession(userId: number, sessionToken: string, dbconn: PoolConnection) {

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

    const result = await query.executeNonQuery();
    if (result.affectedRows === 1) {
      return true;
    } else {
      console.error('Unable to update session date_created');
      return false;
    }
  }

  // #endregion

  // #region USER MANAGEMENT

  private async _getUserInfo(userId: number, dbconn: PoolConnection): Promise<IUserInfo> {
    const qString = `SELECT * FROM ${this.tableNames.userTable} WHERE id=@id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        id: userId
      }
    });

    const rows = await query.executeQuery();
    if (rows.results && rows.results.length > 0) {
      return {
        username: rows.results[0].username,
        email: rows.results[0].email,
        email_verfified: rows.results[0].email_verfified,
        first_name: rows.results[0].first_name,
        last_name: rows.results[0].last_name,
        address_1: rows.results[0].address_1,
        address_2: rows.results[0].address_2,
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
      throw new Error('No matching results found for user');
    }
  }

  private async _getUser(email: string, dbconn: PoolConnection): Promise<UserIdentity>
  private async _getUser(userId: number, dbconn: PoolConnection): Promise<UserIdentity>
  private async _getUser(arg: number | string, dbconn: PoolConnection) {
    let qString = '';
    const qOptions: Partial<IQueryOptions> = {};

    if (typeof arg === 'number') {
      qString = `SELECT id, email, username, first_name, last_name FROM ${this.tableNames.userTable} WHERE id=@id`;
      qOptions.parameters = { id: arg };

    } else if (typeof arg === 'string') {
      qString = `SELECT id, email, username, first_name, last_name FROM ${this.tableNames.userTable} WHERE email=@email`;
      qOptions.parameters = { email: arg };
    } else {
      throw new Error('typeof arg should be number or string');
    }

    const query = new MySqlQuery(qString, dbconn, qOptions);

    const rows = await query.executeQuery();
    if (rows.results && rows.results.length > 0) {
      return new UserIdentity({
        id: rows.results[0].id,
        email: rows.results[0].email,
        first_name: rows.results[0].first_name,
        last_name: rows.results[0].last_name
      })
    } else {
      throw new Error('No user found');
    }
  }

  private async _createNewUser(userInfo: IUserInfo, dbconn: PoolConnection) {
    const qString = `INSERT INTO ${this.tableNames.userTable} (username, email, first_name, last_name, 
      address_1, address_2, country, state, city, zip, company_name, job_title, 
      date_created, phone, dob, email_verified) VALUES (@username, @email, @first_name, @last_name, 
        @address_1, @address_2, @country, @state, @city, @zip, @company_name, @job_title, 
        @date_created, @phone, @dob, @email_verified)`;

    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        username: userInfo.username,
        email: userInfo.email,
        first_name: userInfo.first_name,
        last_name: userInfo.last_name,
        address_1: userInfo.address_1,
        address_2: userInfo.address_2,
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

    const qResult = await query.executeNonQuery();
    const userId = qResult.insertId;

    return await this._getUser(userId, dbconn);
  }

  private async _updateUser(userId: number, userInfo: IUserUpdatePayload, dbconn: PoolConnection) {
    const qString = `UPDATE ${this.tableNames.userTable} SET first_name=@first_name, last_name=@last_name, 
      address_1=@address_1, address_2=@address_2, country=@country, state=@state, city=@city, zip=@zip, company_name=@company_name, job_title=@job_title, 
      phone=@phone, dob=@dob WHERE user_id=@user_id`;

    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        first_name: userInfo.first_name,
        last_name: userInfo.last_name,
        address_1: userInfo.address_1,
        address_2: userInfo.address_2,
        country: userInfo.country,
        state: userInfo.state,
        city: userInfo.city,
        zip: userInfo.zip,
        company_name: userInfo.company_name,
        job_title: userInfo.job_title,
        phone: userInfo.phone,
        dob: userInfo.dob,
        user_id: userId
      }
    });

    const qResult = await query.executeNonQuery();

    return await this._getUser(userId, dbconn);
  }

  private async _isUniqueUsername(username: string, dbconn: PoolConnection) {
    const qString = `SELECT COUNT(id) AS user_count FROM ${this.tableNames.userTable} WHERE username=@username`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        username
      }
    });
    const results = await query.executeScalar<number>();
    return results === 0;
  }

  private async _updateUsername(userId: number, username: string, dbconn: PoolConnection) {
    const qString = `UPDATE ${this.tableNames.userTable} SET username=@username WHERE user_id=@user_id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        username,
        user_id: userId
      }
    });

    const qResult = await query.executeNonQuery();

    return await this._getUser(userId, dbconn);
  }

  // #endregion

  // #region PASSWORD

  private async _updatePassword(payload: IPasswordResetPayload, dbconn: PoolConnection) {

    // Get the count of non expired matching password reset keys
    let qString = `SELECT COUNT(id) FROM ${this.tableNames.passResetKeyStore} WHERE email=@email AND reset_key=@reset_key AND date_created > NOW() - 1;`;
    let query = new MySqlQuery(qString, dbconn, {
      parameters: {
        email: payload.email,
        reset_key: payload.secret
      }
    });

    const count = parseInt(await query.executeScalar(), 10);
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

        const passDelResult = await query.executeNonQuery();
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

        const hashDelResult = await query.executeNonQuery();
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

          const resetDelResult = await query.executeNonQuery();

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

  private async _createPasswordResetKey(email: string, dbconn: PoolConnection) {
    const key = await randomChars(64);
    const qString = `INSERT INTO ${this.tableNames.passResetKeyStore} (email, reset_key, date_created) VALUES (@email, @reset_key, @date_created)`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        email: email,
        reset_key: key,
        date_created: new Date()
      }
    });

    const result = await query.executeNonQuery();
    if (result.affectedRows === 1) {
      return key;
    } else {
      throw new Error('Unable to insert key into database');
    }
  }

  private async _getStoredSaltHash(userId: number, dbconn: PoolConnection) {
    const qString = `SELECT hash_salt from ${this.tableNames.hashSaltStore} WHERE user_id=@user_id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId
      }
    });

    const saltString: string = await query.executeScalar();
    return saltString;
  }

  private async _createUserSaltKey(user: UserIdentity, dbconn: PoolConnection) {
    const salt: string = await generateSalt();
    const qString = `INSERT INTO ${this.tableNames.hashSaltStore} (user_id, hash_salt) VALUES (@user_id, @hash_salt)`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: user.id,
        hash_salt: salt
      }
    });

    const results = await query.executeNonQuery();
    return results.affectedRows === 1 ? salt : undefined;
  }

  private async _storeUserPassword(userId: number, password: string, salt: string, dbconn: PoolConnection) {
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

    const result = await query.executeNonQuery();

    return result.affectedRows === 1 ? true : false;
  }

  //#endregion

  // #region EMAIL

  private async _isUniqueEmail(email: string, dbconn: PoolConnection) {
    const qString = `SELECT COUNT(id) AS user_count FROM ${this.tableNames.userTable} WHERE email=@email`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: { email }
    });
    const results = await query.executeScalar<number>();
    return results === 0;
  }

  private async _updateEmail(userId: number, email: string, dbconn: PoolConnection) {
    const qString = `UPDATE ${this.tableNames.userTable} SET email=@email WHERE user_id=@user_id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        email,
        user_id: userId
      }
    });

    const qResult = await query.executeNonQuery();

    return await this._getUser(userId, dbconn);
  }

  private async _createEmailVerificationKey(userId: number, email: string, dbconn: PoolConnection) {

    // Delete the non matching pending emails
    let qString = `DELETE FROM ${this.tableNames.emailVerifications} WHERE email!=@email AND user_id=@user_id`;
    let query = new MySqlQuery(qString, dbconn, {
      parameters: {
        email,
        user_id: userId
      }
    });

    await query.executeNonQuery();

    // Create the reset token
    const secret = await randomChars(64);

    qString = `INSERT INTO ${this.tableNames.emailVerifications} (user_id, email, secret, date_created) VALUES (@user_id, @email, @secret, @date_created)`;
    query = new MySqlQuery(qString, dbconn, {
      parameters: {
        email,
        user_id: userId,
        secret,
        date_created: new Date()
      }
    });

    const result = await query.executeNonQuery();
    if (result.affectedRows > 0) {
      return secret;
    }
    else {
      throw new Error('An error occurred when attempting to store the Email Verification token');
    }
  }

  private async _verifyEmail(userId: number, email: string, secret: string, dbconn: PoolConnection) {
    let qString = `SELECT COUNT(id) FROM ${this.tableNames.emailVerifications} WHERE secret=@secret AND user_id=@user_id AND email=@email`;
    let query = new MySqlQuery(qString, dbconn, {
      parameters: {
        email,
        secret,
        user_id: userId
      }
    });

    const count = await query.executeScalar<number>();

    if (!count) {
      throw new Error('No matching email verification keys found');
    }

    qString = `UPDATE ${this.tableNames.userTable} email_verified=1 WHERE user_id=@userId`;
    query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId
      }
    });

    let result = await query.executeNonQuery();

    if (!result.affectedRows) {
      throw new Error('An error occurred when attempting to update email verification flag');
    }

    qString = `DELETE FROM ${this.tableNames.emailVerifications} WHERE user_id=@userId`;
    query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: userId
      }
    });

    await query.executeNonQuery();

    return this._getUserInfo(userId, dbconn);
  }

  // #endregion


}