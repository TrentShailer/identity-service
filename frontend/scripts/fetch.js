import { API_KEY, API_KEY_HEADER, API_URL } from "./config.js";

/**
 * @param {"GET" | "POST" | "PUT" | "DELETE" } method
 * @param {string} path
 * @param {*?} body
 * @returns {Promise<ServerResponse<*>>}
 */
async function fetch(method, path, body) {
  const token = localStorage.getItem("token");

  const headers = new Headers();
  headers.append(API_KEY_HEADER, API_KEY);

  if (body) {
    headers.append("content-type", "application/json");
  }
  if (token) {
    headers.append("Authorization", token);
  }

  let bodyContent = null;
  if (body) {
    bodyContent = JSON.stringify(body);
  }

  const response = await self.fetch(API_URL + path, {
    method,
    body: bodyContent,
    headers,
  }).catch(() => {
    return new Response(null, { status: 500 });
  });

  if (response.ok) {
    const bearer = response.headers.get("Authorization");
    if (bearer) {
      localStorage.setItem("token", bearer);
    }

    return {
      status: "ok",
      body: await response.json(), // TODO what about 204
    };
  } else if (response.status === 401) {
    return await logout();
  } else if (response.status >= 400 && response.status < 500) {
    const body = await response.json();
    return {
      status: "clientError",
      problems: body.problems ?? [],
    };
  } else {
    return {
      status: "serverError",
    };
  }
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

  const response = await self.fetch(API_URL + "/tokens/current", {
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

export { fetch, logout };
