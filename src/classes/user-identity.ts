import { PoolConnection } from 'mysql';
import { MySqlQuery } from '../mysql-query';

export interface IUserIdentity {
  id: number;
  username: string;
  fname: string;
  lname: string;
  roles: string[];
  email: string;
}

export class UserIdentity implements IUserIdentity {
  id: number = 0;
  username: string = '';
  fname: string = '';
  lname: string = '';
  roles: string[] = [];
  email: string = '';

  constructor(init?: Partial<IUserIdentity>) {
    if (init) {
      if (init.email) this.email = init.email;
      if (init.fname) this.fname = init.fname;
      if (init.lname) this.lname = init.lname;
      if (init.roles) this.roles = init.roles;
      if (init.id) this.id = init.id;
      if (init.username) this.username = init.username;
    }
  }

  public async getUserRoles(tablename: string, dbconn: PoolConnection) {
    this.roles = new Array<string>();
    const qString = `SELECT * FROM ${tablename} WHERE user_id=@user_id`;
    const query = new MySqlQuery(qString, dbconn, {
      parameters: {
        user_id: this.id
      }
    });

    const rows = await query.executeQueryAsync();
    if (rows.results) {
      for (const row of rows.results) {
        this.roles.push(row.claim);
      }
    }
    return;
  }
}