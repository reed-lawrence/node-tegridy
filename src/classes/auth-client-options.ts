export interface IAuthClientOptions {
  /**
   * The name of the auth database containing the required schema tables (Default: auth_server)
   */
  dbname?: string;

  /**
   * The hostname of the database you are connecting to. (Default: localhost)
   */
  host?: string;

  /**
   * The port number to connect to. (Default: 3306)
   */
  port?: number;

  /**
   * The user that the AuthClient instance will use when accessing the database (Default: root)
   */
  user?: string;

  /**
   * The password that the AuthClient instance will use when accessing the database (Default: none)
   */
  password?: string;

  /**
   * Options to provide to the AuthClient
   */
  opts?: {

    /**
     * Number of concurrent sessions allowed to be open. The oldest session token 
     * will be removed when the session count exceeds the specified number.
     * (Default: unlimited)
     */
    concurrent_sessions?: number;

    /**
     * Number of times a password will be hashed via pbkdf2 cyrptography
     * (Default: 100)
     */
    hash_iterations?: number;
  }
}