import { ICacheService } from "../services/cache-service";
import { IUserInfo } from "../types/user-info";

export interface IAuthClientOptions {
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

  /**
   * Specify which fields should be unique
   * (Default: email)
   */
  unique_user_fields?: (keyof IUserInfo)[];

  /**
   * The service to utilize for session caching
   */
  cache_service?: ICacheService;
}