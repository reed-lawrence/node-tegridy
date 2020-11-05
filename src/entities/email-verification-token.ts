export interface IEmailVerificationToken {
  id: number;
  user_id: number;
  email: string;
  secret: string;
  date_created: string;
}

export class EmailVerificationToken implements IEmailVerificationToken {

  id: number = 0;
  user_id: number = 0;
  email: string = '';
  secret: string = '';
  date_created: string = '';

  constructor(init?: Partial<IEmailVerificationToken>) {

    if (init) {
      if (init.id) { this.id = init.id; }
      if (init.user_id) { this.user_id = init.user_id; }
      if (init.email) { this.email = init.email; }
      if (init.secret) { this.secret = init.secret; }
      if (init.date_created) { this.date_created = init.date_created; }
    }

  }
}