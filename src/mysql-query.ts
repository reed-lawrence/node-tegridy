import { PoolConnection, escape, FieldInfo } from "mysql";

export interface IQueryOptions {
  parameters: object;
  queryFormat: (query: string, values: any) => string;
}

export class MySqlQuery {
  private dbconn: PoolConnection;

  public parameters: { [index: string]: any } = {};
  public qString: string;
  public queryFormat = (query: string, values: any) => {
    if (!values) return query;
    return query.replace(/[@](\w+)/g, (txt, key) => {
      if (values.hasOwnProperty(key)) {
        return escape(values[key]);
      }
      return txt;
    });
  };

  constructor(qString: string, connection: PoolConnection, options?: Partial<IQueryOptions>) {
    this.qString = qString;
    this.dbconn = connection;

    if (options) {
      if (options.parameters) this.parameters = options.parameters;
      if (options.queryFormat) this.queryFormat = options.queryFormat;
    }
  }

  private queryAsync() {
    return new Promise<{ results: any, fields: FieldInfo[] | undefined }>((resolve, reject) => {

      this.dbconn.query(this.queryFormat(this.qString, this.parameters), (err, results, fields) => {
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