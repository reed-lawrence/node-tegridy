import { PoolConnection } from 'mysql';
import { MySqlQuery } from '@reed-lawrence/mysql-query';

export interface IUserIdentity {
  id: number;
  username: string;
  first_name: string;
  last_name: string;
  roles: string[];
  email: string;
}

export class UserIdentity implements IUserIdentity {
  id: number = 0;
  username: string = '';
  first_name: string = '';
  last_name: string = '';
  roles: string[] = [];
  email: string = '';

  constructor(init?: Partial<IUserIdentity>) {
    if (init) {
      if (init.email) this.email = init.email;
      if (init.first_name) this.first_name = init.first_name;
      if (init.last_name) this.last_name = init.last_name;
      if (init.roles) this.roles = init.roles;
      if (init.id) this.id = init.id;
      if (init.username) this.username = init.username;
    }
  }
}