import { UserIdentity } from "../types/user-identity";

export interface ILoginResponse {
  user: UserIdentity;
  sessionToken: string;
}