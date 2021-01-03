export interface IToken {
  value: string;
  date_created: string;
}

export interface IAntiForgeryToken extends IToken { }

export class AntiForgeryToken implements IAntiForgeryToken {
  value: string = '';
  date_created: string = '';

  constructor(init?: Partial<IAntiForgeryToken>) {
    Object.assign(this, init);
  }
}

export interface ISessionToken extends IToken {
  id: number;
  selector: string;
  validator: string;
  user_id: number;
}

export class SessionToken implements ISessionToken {
  id: number = 0;
  selector: string = '';
  validator: string = '';
  user_id: number = 0;
  value: string = '';
  date_created: string = '';

  constructor(init?: Partial<ISessionToken>) {
    Object.assign(this, init);
  }
}