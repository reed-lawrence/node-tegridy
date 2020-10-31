import { MySqlQuery } from "@reed-lawrence/mysql-query";
import { createPool, Pool, PoolConfig, PoolConnection, escape } from "mysql";
import { AuthTableNames } from "./constants/table-names";

export class AuthTesting {

  constructor(dbconfig: PoolConfig) {
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
  }

  public pool: Pool;

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

  public dispose() {
    this.pool.end();
  }

}