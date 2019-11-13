import mysql from 'mysql';

export interface IQueryOptions {
  parameters: object;
}

export class MySqlQuery {
  public parameters: {
    [index: string]: any
  } = {};
  public qString: string;
  private dbconn: mysql.PoolConnection;

  constructor(qString: string, connection: mysql.PoolConnection, options?: Partial<IQueryOptions>) {
    this.qString = qString;
    this.dbconn = connection;

    if (options) {
      if (options.parameters) this.parameters = options.parameters;
    }
  }

  private queryAsync() {
    return new Promise<{ results: any, fields: mysql.FieldInfo[] | undefined }>((resolve, reject) => {
      this.dbconn.query(this.qString, this.parameters, (err, results, fields) => {
        if (err) return reject(err);
        return resolve({ results, fields });
      });
    });
  }

  public executeNonQueryAsync() {
    return new Promise<any>((resolve, reject) => {
      this.queryAsync().then(q => {
        return resolve(q.results);
      }).catch(err => {
        return reject(err);
      })
    });
  }

  public executeQueryAsync() {
    return this.queryAsync();
  }

  public executeScalarAsync<T>() {
    return new Promise<T>((resolve, reject) => {
      this.queryAsync().then(q => {
        const scalarObj = Object.assign({}, q.results[0]);
        if (!scalarObj) {
          throw new Error('Unable to determine a scalar result to output');
        } else {
          const output = scalarObj[Object.keys(scalarObj)[0]];
          return resolve(output);
        }
      }).catch(err => reject(err));
    });
  }
}