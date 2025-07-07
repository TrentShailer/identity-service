import { fetch, logout } from "./fetch.js";

/**
 * @returns {Promise<TokenDetails | never>}
 */
async function getCurrentToken() {
  const token = localStorage.getItem("token");
  if (!token) {
    return await logout();
  }

  const response = await fetch("GET", "/tokens/current", null);

  if (response.status !== "ok") {
    alert("Received an error response from the server - logging out.");
    return await logout();
  }
  if (!response.body.sub || !response.body.typ || !response.body.exp) {
    alert("Received an invalid response from the server - logging out.");
    return await logout();
  }

  return { bearer: token, ...response.body };
}

export { getCurrentToken, logout };
