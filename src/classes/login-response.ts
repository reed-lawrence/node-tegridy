import { UserIdentity } from "../entities/user-identity";

export interface ILoginResponse {
  user: UserIdentity;
  sessionToken: string;
}