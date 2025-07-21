export const API_URL = "http://localhost:8081";
/** @type import("../lib/fetch.js").Header */
export const API_KEY = ["X-TS-API-Key", "identity-site"];
/** @type import("../lib/fetch.js").LogoutConfig */
export const LOGOUT_CONFIG = {
  endpoint: API_URL + "/tokens/current",
  redirect: "/login", // TODO redirect
};
