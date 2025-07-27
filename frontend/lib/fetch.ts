import { base64Decode } from "./base64.ts";

declare global {
  namespace globalThis {
    var tokenDomain: string | undefined;
  }

  interface Window {
    cookieStore: CookieStore;
  }

  type Cookie = {
    domain: string;
    expires: number;
    name: string;
    path: string;
    sameSite: "strict" | "lax" | "none";
    secure: boolean;
    value: string;
  };

  interface CookieStore {
    delete(name: string): Promise<undefined>;
    delete(options: {
      name: string;
      domain: string | undefined;
      path: string | undefined;
      partitioned: boolean | undefined;
    }): Promise<undefined>;

    get(name: string): Promise<Cookie | null>;
    get(options: { name: string; url: string }): Promise<Cookie | null>;

    set(name: string, value: string): Promise<undefined>;
    set(
      options: {
        domain: string | undefined;
        expires: number | undefined;
        name: string;
        partitioned: boolean | undefined;
        path: string | undefined;
        sameSite: "strict" | "lax" | "none" | undefined;
        value: string;
      },
    ): Promise<undefined>;
  }
}

export type Problem = {
  pointer: string;
  detail: string;
};

export type ServerResponse<T> =
  | { status: "ok"; body: T }
  | { status: "badRequest"; problems: Problem[] }
  | { status: "unauthenticated" }
  | { status: "error" }
  | never;

export type Header = [string, string];

export const TOKEN_KEY = "ts_token";

export class FetchBuilder {
  #method: "GET" | "POST" | "PUT" | "DELETE";
  #url: string;
  #additionalHeaders: Header[] | null = null;
  #body: object | null = null;

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

  async fetch<T>(): Promise<ServerResponse<T>> {
    return await fetch(
      this.#method,
      this.#url,
      this.#additionalHeaders,
      this.#body,
    );
  }
}

export function setConfig(tokenDomain: string) {
  Object.defineProperty(globalThis, "tokenDomain", {
    value: tokenDomain,
    writable: true,
    configurable: true,
  });
}

export async function getToken(): Promise<
  // deno-lint-ignore no-explicit-any
  { bearer: string; claims: any } | null
> {
  const token = await globalThis.window.cookieStore.get(TOKEN_KEY);
  if (!token) {
    return null;
  }

  const parts = token.value.split(".");
  if (parts.length !== 3) {
    await deleteToken();
    return null;
  }

  const decoder = new TextDecoder();
  const claims = JSON.parse(decoder.decode(base64Decode(parts[1])));

  return {
    bearer: token.value,
    claims,
  };
}

export async function deleteToken(): Promise<undefined> {
  console.info("deleting token");
  await globalThis.window.cookieStore.delete(TOKEN_KEY);
  return undefined;
}

export async function setToken(token: string): Promise<undefined> {
  if (globalThis.tokenDomain == undefined || globalThis.tokenDomain == null) {
    throw new Error("`globalThis.tokenDomain` has not been set, token cannot be saved.");
  }
  console.info("setting token");
  await globalThis.window.cookieStore.set({
    domain: globalThis.tokenDomain,
    name: TOKEN_KEY,
    value: token,
    sameSite: "strict",
    expires: Date.now() + 1000 * 60 * 60 * 24 * 30,
    partitioned: undefined,
    path: undefined,
  });
  return undefined;
}

export async function fetch<T>(
  method: "GET" | "POST" | "PUT" | "DELETE",
  url: string,
  additionalHeaders: Header[] | null,
  body: object | null,
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

  const token = await getToken();
  if (token && !headers.has("Authorization")) {
    headers.append("Authorization", token.bearer);
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
      await setToken(bearer);
    }

    const body = await response.json().catch((ex) => {
      console.warn(ex);
      return {};
    });

    return {
      status: "ok",
      body,
    };
  }

  switch (response.status) {
    case 400: {
      const body = await response.json().catch((ex) => {
        console.warn(ex);
        return { problems: [] };
      });

      return {
        status: "badRequest",
        problems: body.problems ?? [],
      };
    }
    case 401:
    case 403: {
      return { status: "unauthenticated" };
    }
  }

  return { status: "error" };
}
