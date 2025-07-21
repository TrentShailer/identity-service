import { Header, LogoutConfig } from "../lib/fetch.ts";

export const API_URL = "http://localhost:8081";
export const API_KEY: Header = ["X-TS-API-Key", "identity-site"];

export const LOGOUT_CONFIG: LogoutConfig = {
  deleteTokenEndpoint: API_URL + "/tokens/current",
  loginHref: "/login",
  additionalHeaders: [API_KEY],
};
