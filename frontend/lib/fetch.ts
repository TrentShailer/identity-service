import { setHref } from "./redirect.ts";

export type Problem = {
  pointer: string | null;
  detail: string | null;
};

export type ServerResponse<T> =
  | { status: "ok"; body: T }
  | { status: "clientError"; problems: Problem[] }
  | { status: "serverError" }
  | { status: "unauthorized" }
  | { status: "notFound" }
  | never;

export type LogoutConfig = {
  deleteTokenEndpoint: string;
  loginHref: string;
  additionalHeaders: Header[];
};

export type Header = [string, string];

export const TOKEN_KEY = "token";

export class FetchBuilder {
  #method: "GET" | "POST" | "PUT" | "DELETE";
  #url: string;
  #additionalHeaders: Header[] | null = null;
  #body: object | null = null;
  #logoutConfig: LogoutConfig | null = null;
  #logoutShouldReturn: boolean = false;

  constructor(method: "GET" | "POST" | "PUT" | "DELETE", url: string) {
    this.#method = method;
    this.#url = url;
  }

  setBody(body: object | null): FetchBuilder {
    this.#body = body;
    return this;
  }

  setHeaders(headers: Header[] | null): FetchBuilder {
    this.#additionalHeaders = headers;
    return this;
  }

  setLogout(logoutConfig: LogoutConfig | null, shouldReturn: boolean): FetchBuilder {
    this.#logoutConfig = logoutConfig;
    this.#logoutShouldReturn = shouldReturn;
    return this;
  }

  async fetch<T>(): Promise<ServerResponse<T>> {
    return await fetch(
      this.#method,
      this.#url,
      this.#additionalHeaders,
      this.#body,
      this.#logoutConfig,
      this.#logoutShouldReturn,
    );
  }
}

export async function fetch<T>(
  method: "GET" | "POST" | "PUT" | "DELETE",
  url: string,
  additionalHeaders: Header[] | null,
  body: object | null,
  logoutConfig: LogoutConfig | null,
  logoutShouldReturn: boolean,
): Promise<ServerResponse<T>> {
  const headers = new Headers();

  if (additionalHeaders) {
    for (const header of additionalHeaders) {
      headers.append(header[0], header[1]);
    }
  }

  if (body) {
    headers.append("content-type", "application/json");
  }

  const token = localStorage.getItem(TOKEN_KEY);
  if (token && !headers.has("Authorization")) {
    headers.append("Authorization", token);
  }

  let bodyContent = null;
  if (body) {
    bodyContent = JSON.stringify(body);
  }

  const response = await self.fetch(url, {
    method,
    body: bodyContent,
    headers,
  }).catch((ex) => {
    console.warn(ex);
    return new Response(null, { status: 500 });
  });

  if (response.ok) {
    const bearer = response.headers.get("Authorization");
    if (bearer) {
      localStorage.setItem(TOKEN_KEY, bearer);
    }

    const body = await response.json().catch((ex) => {
      console.warn(ex);
      return {};
    });

    return {
      status: "ok",
      body,
    };
  } else if (response.status === 401) {
    if (logoutConfig) {
      await logout(
        logoutConfig,
        logoutShouldReturn,
      );
    }

    return { status: "unauthorized" };
  } else if (response.status === 404) {
    return { status: "notFound" };
  } else if (response.status >= 400 && response.status < 500) {
    const body = await response.json().catch((ex) => {
      console.warn(ex);
      return { problems: [] };
    });

    return {
      status: "clientError",
      problems: body.problems ?? [],
    };
  } else {
    return { status: "serverError" };
  }
}

export async function logout(
  config: LogoutConfig,
  shouldReturn: boolean,
): Promise<never> {
  const token = localStorage.getItem(TOKEN_KEY);
  await new FetchBuilder("DELETE", config.deleteTokenEndpoint).setHeaders(config.additionalHeaders)
    .fetch();
  localStorage.removeItem(TOKEN_KEY);

  if (token) {
    alert("Your session has expired");
  }

  const href = shouldReturn
    ? `${config.loginHref}?redirect=${encodeURI(location.href)}`
    : config.loginHref;

  return await setHref(href);
}
