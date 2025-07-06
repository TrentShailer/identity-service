import { API_KEY, API_KEY_HEADER, API_URL } from "./config.js";

/**
 * @returns {Promise<TokenDetails | never>}
 */
async function getCurrentToken() {
  const token = localStorage.getItem("token");
  if (!token) {
    return await logout();
  }

  const headers = new Headers();
  headers.append(API_KEY_HEADER, API_KEY);
  headers.append("Authorization", token);

  const response = await fetch(API_URL + "/tokens/current", {
    method: "GET",
    headers,
  });

  if (response.status === 401) {
    return await logout();
  } else if (response.status !== 200) {
    alert("Received an invalid response from the server - logging out.");
    return await logout();
  }

  const body = await response.json();
  if (!body.sub || !body.typ || !body.exp) {
    alert("Received an invalid response from the server - logging out.");
    return await logout();
  }

  return { bearer: token, ...body };
}

/**
 * @returns {Promise<never>}
 */
async function logout() {
  const token = localStorage.getItem("token");
  localStorage.removeItem("token");
  if (!token) {
    location.href = "/login";
    // @ts-ignore href should always redirect before return.
    return;
  }

  const headers = new Headers();
  headers.append(API_KEY_HEADER, API_KEY);
  headers.append("Authorization", token);

  const response = await fetch(API_URL + "/tokens/current", {
    method: "DELETE",
    headers,
  });

  if (response.status === 401) {
    alert("Your session has expired - logging out.");
  }

  location.href = "/login";
  // @ts-ignore href should always redirect before return.
  return;
}

export { getCurrentToken, logout };
