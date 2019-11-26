import { UserIdentity } from "./user-identity";

export interface ILoginResponse {
  user: UserIdentity;
  sessionToken: string;
}