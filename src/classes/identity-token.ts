export interface IIdentityToken {
  id: number;
  selector: string;
  validator: string;
  user_id: number;
  date_created: string;
}

export class IdentityToken implements IIdentityToken {
  id: number = 0;
  selector: string = '';
  validator: string = '';
  user_id: number = 0;
  date_created: string = ''

  constructor(init?: Partial<IIdentityToken>) {
    if (init) {
      if (init.id) this.id = init.id;
      if (init.selector) this.selector = init.selector;
      if (init.validator) this.validator = init.validator;
      if (init.user_id) this.user_id = init.user_id;
      if (init.date_created) this.date_created = init.date_created;
    }
  }
}