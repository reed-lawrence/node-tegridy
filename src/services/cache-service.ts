import { AntiForgeryToken, IAntiForgeryToken, ISessionToken, SessionToken } from "../types/tokens";
import { IUserIdentity, UserIdentity } from "../types/user-identity";

export interface ICacheEntity<TKey extends number | string, TValue> {
  Get(key: TKey): TValue | undefined;
  Cache(value: TValue): void;
  Remove(key: TKey): void;
  RemoveRange(keys: TKey[]): void;
}

export class CacheEntity<TKey extends number | string, TValue> implements ICacheEntity<TKey, TValue> {

  private readonly dict = new Map<TKey, TValue>();

  private readonly keyFn: (obj: TValue) => TKey;

  constructor(keyFn: (obj: TValue) => TKey) {
    this.keyFn = keyFn;
  }

  Get(key: TKey) {
    return this.dict.get(key);
  }

  Cache(value: TValue) {
    this.dict.set(this.keyFn(value), value);
  }

  Remove(key: TKey) {
    this.dict.delete(key);
  }

  RemoveRange(keys: TKey[]) {
    for (let i = 0; i < keys.length; i++) {
      this.dict.delete(keys[i]);
    }
    const test = new AntiForgeryToken()
  }
}

export interface ICacheService {
  AntiForgeryTokens: ICacheEntity<string, IAntiForgeryToken>;
  SessionTokens: ICacheEntity<string, ISessionToken>;
  Users: ICacheEntity<number, IUserIdentity>;
}

export class CacheService implements ICacheService {

  private readonly _antiForgeryTokens = new CacheEntity<string, AntiForgeryToken>((o) => o.value);
  public get AntiForgeryTokens() {
    return this._antiForgeryTokens;
  }

  private readonly _sessionTokens = new CacheEntity<string, SessionToken>((o) => o.value);
  public get SessionTokens() {
    return this._sessionTokens;
  }

  private readonly _users = new CacheEntity<number, UserIdentity>((o) => o.id);
  public get Users() {
    return this._users;
  }

}