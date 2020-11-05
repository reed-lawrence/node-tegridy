export interface IPasswordResetRequest {
  id: number;
  email: string;
  reset_key: string;
  date_created: string;
}

export class PasswordResetRequest implements IPasswordResetRequest {
  id: number = 0;
  email: string = '';
  reset_key: string = '';
  date_created: string = '';

  constructor(init?: Partial<IPasswordResetRequest>) {
    if (init) {
      if (init.id) { this.id = init.id; }
      if (init.email) { this.email = init.email; }
      if (init.reset_key) { this.reset_key = init.reset_key; }
      if (init.date_created) { this.date_created = init.date_created; }
    }
  }
}