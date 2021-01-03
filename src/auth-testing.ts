import { MySqlQuery } from "@reed-lawrence/mysql-query";
import { createPool, Pool, PoolConfig, PoolConnection, escape } from "mysql";
import { AuthClient } from "./auth-client";
import { IAuthClientOptions } from "./classes/auth-client-options";
import { EmailVerificationToken } from "./types/email-verification-token";
import { AuthTableNames } from "./constants/table-names";
import { PasswordResetRequest } from "./types/password-reset-request";

export class AuthTesting {

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

    this.pool = createPool(dbconfig);
    this.client = new AuthClient(dbconfig, options);
  }

  public pool: Pool;
  public client: AuthClient;

  private readonly tables = AuthTableNames;

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

  public async ResetAuthTables() {
    const dbconn = await this.getConnection();

    for (const key in this.tables) {
      //@ts-ignore
      const qString = `DELETE FROM ${this.tables[key]};`;
      const query = new MySqlQuery(qString, dbconn);
      try {
        await query.executeNonQuery();
      } catch (error) {
        dbconn.release();
        throw error;
      }
    }

    dbconn.release();
    return;
  }

  public async GetEmailVerificationTokens() {
    const dbconn = await this.getConnection();
    const output: EmailVerificationToken[] = [];

    try {
      const qString = `SELECT * FROM ${this.tables.emailVerifications}`;
      const query = new MySqlQuery(qString, dbconn);
      var rows = await query.executeQuery();

      if (rows.results && rows.results.length > 0) {
        for (const row of rows.results) {
          output.push(new EmailVerificationToken({
            id: row.id,
            user_id: row.user_id,
            date_created: row.date_created,
            email: row.email,
            secret: row.secret
          }));
        }
      }

      dbconn.release();
      return output;

    } catch (error) {
      dbconn.release();
      throw error;
    }
  }

  public async GetPasswordResetRequests(){
    const dbconn = await this.getConnection();
    const output: PasswordResetRequest[] = [];

    try {
      const qString = `SELECT * FROM ${this.tables.passResetKeyStore}`;
      const query = new MySqlQuery(qString, dbconn);
      var rows = await query.executeQuery();

      if (rows.results && rows.results.length > 0) {
        for (const row of rows.results) {
          output.push(new PasswordResetRequest({
            id: row.id,
            date_created: row.date_created,
            email: row.email,
            reset_key: row.reset_key
          }));
        }
      }

      dbconn.release();
      return output;

    } catch (error) {
      dbconn.release();
      throw error;
    }
  }

  public dispose() {
    this.pool.end();
  }

}